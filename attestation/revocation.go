package attestation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const googleStatusURL = "https://android.googleapis.com/attestation/status"
const maxStatusBytes = 2 << 20
const maxStatusAge = 5 * time.Minute

type googleRevocations struct {
	mu      sync.Mutex
	client  *http.Client
	expires time.Time
	entries map[string]struct{}
}

// NewGoogleRevocations returns a fail-closed checker for Google's fixed HTTPS
// endpoint. The optional HTTP client supplies transport configuration; redirects
// are forbidden and a ten-second timeout is imposed. Cache freshness is bounded
// by both HTTP cache headers and a local five-minute ceiling.
func NewGoogleRevocations(client *http.Client) RevocationChecker {
	c := http.Client{}
	if client != nil {
		c = *client
	}
	if c.Timeout <= 0 || c.Timeout > 10*time.Second {
		c.Timeout = 10 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("attestation status redirect refused") }
	return &googleRevocations{client: &c}
}
func (g *googleRevocations) Check(ctx context.Context, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("empty revocation chain")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.entries == nil || !now.Before(g.expires) {
		entries, expires, e := g.fetch(ctx, now)
		if e != nil {
			return e
		}
		g.entries = entries
		g.expires = expires
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	for _, c := range chain {
		if c == nil || c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
			return errors.New("invalid attestation certificate serial")
		}
		if _, listed := g.entries[c.SerialNumber.Text(16)]; listed {
			return errors.New("attestation certificate revoked or suspended")
		}
	}
	return nil
}
func (g *googleRevocations) fetch(ctx context.Context, now time.Time) (map[string]struct{}, time.Time, error) {
	fail := func(e error) (map[string]struct{}, time.Time, error) { return nil, time.Time{}, e }
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, googleStatusURL, nil)
	if e != nil {
		return fail(e)
	}
	req.Header.Set("Accept", "application/json")
	resp, e := g.client.Do(req)
	if e != nil {
		return fail(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("Google status HTTP %d", resp.StatusCode))
	}
	date, e := http.ParseTime(resp.Header.Get("Date"))
	if e != nil || date.After(now.Add(time.Minute)) || now.Sub(date) > maxStatusAge {
		return fail(errors.New("missing or stale Google status Date"))
	}
	age := time.Duration(0)
	if h := resp.Header.Get("Age"); h != "" {
		a, e := strconv.ParseInt(h, 10, 32)
		if e != nil || a < 0 {
			return fail(errors.New("invalid status Age"))
		}
		age = time.Duration(a) * time.Second
	}
	if elapsed := now.Sub(date); elapsed > age {
		age = elapsed
	}
	ttl := maxStatusAge
	for _, directive := range strings.Split(resp.Header.Get("Cache-Control"), ",") {
		d := strings.TrimSpace(strings.ToLower(directive))
		if d == "no-store" || d == "no-cache" {
			ttl = 0
		}
		if strings.HasPrefix(d, "max-age=") {
			seconds, e := strconv.ParseInt(strings.TrimPrefix(d, "max-age="), 10, 32)
			if e != nil || seconds < 0 {
				return fail(errors.New("invalid status max-age"))
			}
			duration := time.Duration(seconds) * time.Second
			if duration < ttl {
				ttl = duration
			}
		}
	}
	if age >= ttl {
		return fail(errors.New("stale Google status response"))
	}
	expires := now.Add(ttl - age)
	body, e := io.ReadAll(io.LimitReader(resp.Body, maxStatusBytes+1))
	if e != nil {
		return fail(e)
	}
	if len(body) > maxStatusBytes {
		return fail(errors.New("Google status body too large"))
	}
	if e = uniqueJSON(body); e != nil {
		return fail(e)
	}
	var document struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if e = json.Unmarshal(body, &document); e != nil || document.Entries == nil {
		return fail(errors.New("invalid Google status entries"))
	}
	out := map[string]struct{}{}
	for serial, raw := range document.Entries {
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok || n.Sign() <= 0 || len(serial) > 64 {
			return fail(errors.New("invalid status serial"))
		}
		canonical := n.Text(16)
		if _, exists := out[canonical]; exists {
			return fail(errors.New("duplicate status serial"))
		}
		var entry struct {
			Status string `json:"status"`
		}
		if e = json.Unmarshal(raw, &entry); e != nil || (entry.Status != "REVOKED" && entry.Status != "SUSPENDED") {
			return fail(errors.New("unknown or malformed certificate status"))
		}
		out[canonical] = struct{}{}
	}
	if !time.Now().Before(expires) {
		return fail(errors.New("Google status expired during fetch"))
	}
	return out, expires, nil
}

// encoding/json otherwise silently accepts duplicate object members. Reject
// those before unmarshalling security decisions, with depth and token budgets.
func uniqueJSON(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	budget := 200000
	var value func(int) error
	value = func(depth int) error {
		budget--
		if depth > 8 || budget < 0 {
			return errors.New("status JSON complexity limit")
		}
		tok, e := d.Token()
		if e != nil {
			return e
		}
		delimiter, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON member")
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing status JSON")
	}
	return nil
}

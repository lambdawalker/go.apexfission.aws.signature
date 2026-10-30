package attestation

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGoogleRevocations(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		age        string
		fetchError bool
		bad        bool
	}{
		{name: "fresh clean", body: `{"entries":{}}`, status: 200},
		{name: "revoked leaf", body: `{"entries":{"2":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`, status: 200, bad: true},
		{name: "revoked root", body: `{"entries":{"1":{"status":"SUSPENDED"}}}`, status: 200, bad: true},
		{name: "unrecognized", body: `{"entries":{"2":{"status":"GOOD"}}}`, status: 200, bad: true},
		{name: "duplicate", body: `{"entries":{},"entries":{}}`, status: 200, bad: true},
		{name: "null", body: `{"entries":null}`, status: 200, bad: true},
		{name: "trailing", body: `{"entries":{}}{}`, status: 200, bad: true},
		{name: "fetch failure", fetchError: true, bad: true},
		{name: "bad status", status: 500, bad: true},
		{name: "stale", body: `{"entries":{}}`, status: 200, age: "301", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain, _, _ := fixture(t, []byte{5, 0})
			var certs []*x509.Certificate
			for _, b := range chain {
				c, _ := x509.ParseCertificate(b)
				certs = append(certs, c)
			}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://android.googleapis.com/attestation/status" {
					t.Fatal("wrong endpoint")
				}
				if tc.fetchError {
					return nil, errors.New("network unavailable")
				}
				h := http.Header{"Date": {time.Now().UTC().Format(http.TimeFormat)}, "Cache-Control": {"max-age=300"}}
				if tc.age != "" {
					h.Set("Age", tc.age)
				}
				return &http.Response{StatusCode: tc.status, Header: h, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			e := NewGoogleRevocations(client).Check(context.Background(), certs)
			if (e != nil) != tc.bad {
				t.Fatalf("error = %v, want failure %v", e, tc.bad)
			}
		})
	}
}
func TestGoogleCacheRefreshFailsClosed(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			return nil, errors.New("offline")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Date": {time.Now().UTC().Format(http.TimeFormat)}, "Cache-Control": {"max-age=1"}}, Body: io.NopCloser(strings.NewReader(`{"entries":{}}`))}, nil
	})}
	chain, _, _ := fixture(t, []byte{5, 0})
	c, _ := x509.ParseCertificate(chain[0])
	g := NewGoogleRevocations(client).(*googleRevocations)
	if e := g.Check(context.Background(), []*x509.Certificate{c}); e != nil {
		t.Fatal(e)
	}
	if e := g.Check(context.Background(), []*x509.Certificate{c}); e != nil || calls != 1 {
		t.Fatal("fresh cache not used", e, calls)
	}
	g.expires = time.Now().Add(-time.Second)
	if e := g.Check(context.Background(), []*x509.Certificate{c}); e == nil {
		t.Fatal("stale cache accepted on fetch failure")
	}
}

func TestGoogleRejectsRedirectAndOversize(t *testing.T) {
	for _, name := range []string{"redirect", "oversize", "missing date", "duplicate serial"} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				h := http.Header{"Date": {time.Now().UTC().Format(http.TimeFormat)}}
				status := 200
				body := `{"entries":{}}`
				switch name {
				case "redirect":
					status = 302
					h.Set("Location", "http://attacker.invalid/status")
				case "oversize":
					body = strings.Repeat(" ", maxStatusBytes+1)
				case "missing date":
					h.Del("Date")
				case "duplicate serial":
					body = `{"entries":{"02":{"status":"REVOKED"},"2":{"status":"SUSPENDED"}}}`
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			chain, _, _ := fixture(t, []byte{5, 0})
			c, _ := x509.ParseCertificate(chain[0])
			if e := NewGoogleRevocations(client).Check(context.Background(), []*x509.Certificate{c}); e == nil {
				t.Fatal("accepted unsafe response")
			}
		})
	}
}

// Package attestation verifies a deliberately strict Android hardware signing policy.
package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var attestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

type RevocationChecker interface {
	Check(context.Context, []*x509.Certificate) error
}
type Policy struct {
	Roots            *x509.CertPool
	AppPackage       string
	AppSignerDigests [][]byte
	Now              func() time.Time
	Revocations      RevocationChecker
}
type Verifier struct{ Policy Policy }
type Result struct {
	PublicKey          *ecdsa.PublicKey `json:"-"`
	KeyID              string           `json:"keyId"`
	SecurityLevel      string           `json:"securityLevel"`
	AttestationVersion int              `json:"attestationVersion"`
	AppPackage         string           `json:"appPackage"`
}

func (v *Verifier) Verify(ctx context.Context, chainDER [][]byte, nonce []byte, suite string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := v.Policy
	if p.Roots == nil || p.Revocations == nil || p.AppPackage == "" || len(p.AppSignerDigests) == 0 {
		return nil, errors.New("incomplete attestation policy")
	}
	for _, d := range p.AppSignerDigests {
		if len(d) != 32 {
			return nil, errors.New("signer digest must be SHA256")
		}
	}
	level := 1
	name := "TEE"
	switch suite {
	case "ES256_TEE":
	case "ES256_STRONGBOX":
		level = 2
		name = "STRONGBOX"
	default:
		return nil, errors.New("unsupported suite")
	}
	if len(nonce) != 32 || len(chainDER) < 2 || len(chainDER) > 8 {
		return nil, errors.New("invalid nonce or chain count")
	}
	certs := make([]*x509.Certificate, len(chainDER))
	total := 0
	for i, b := range chainDER {
		total += len(b)
		if len(b) == 0 || len(b) > 64<<10 || total > 256<<10 {
			return nil, errors.New("certificate size limit")
		}
		c, e := x509.ParseCertificate(b)
		if e != nil {
			return nil, e
		}
		certs[i] = c
	}
	leaf := certs[0]
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("leaf must be a P256 signing key")
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	paths, e := leaf.Verify(x509.VerifyOptions{Roots: p.Roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if e != nil {
		return nil, fmt.Errorf("attestation path: %w", e)
	}
	// Every submitted certificate must belong to the verified leaf-first path. In
	// particular, request certificates are never added to the trusted root pool.
	var path []*x509.Certificate
	for _, candidate := range paths {
		if len(candidate) != len(certs) {
			continue
		}
		match := true
		for i := range certs {
			if !bytes.Equal(certs[i].Raw, candidate[i].Raw) {
				match = false
				break
			}
		}
		if match {
			path = candidate
			break
		}
	}
	if path == nil {
		return nil, errors.New("submitted chain is not the verified path")
	}
	var ext []byte
	for i, c := range path {
		for _, x := range c.Extensions {
			if x.Id.Equal(attestationOID) {
				if i != 0 || ext != nil {
					return nil, errors.New("ambiguous attestation extension")
				}
				ext = x.Value
			}
		}
	}
	if len(ext) == 0 || len(ext) > 32<<10 {
		return nil, errors.New("missing or oversized attestation")
	}
	r, e := parseRecord(ext, nonce, level, p)
	if e != nil {
		return nil, e
	}
	if e = p.Revocations.Check(ctx, path); e != nil {
		return nil, fmt.Errorf("attestation revocation: %w", e)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return &Result{PublicKey: key, KeyID: hex.EncodeToString(sum[:]), SecurityLevel: name, AttestationVersion: r, AppPackage: p.AppPackage}, nil
}

type node = asn1.RawValue

func decode(b []byte) (node, error) {
	var n node
	rest, e := asn1.Unmarshal(b, &n)
	if e != nil || len(rest) != 0 {
		return n, errors.New("malformed DER value")
	}
	return n, nil
}
func children(n node, tag int) ([]node, error) {
	if n.Class != 0 || n.Tag != tag || !n.IsCompound {
		return nil, errors.New("unexpected DER container")
	}
	var out []node
	for b := n.Bytes; len(b) > 0; {
		if len(out) >= 128 {
			return nil, errors.New("DER child limit")
		}
		var c node
		rest, e := asn1.Unmarshal(b, &c)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}
func number(n node, tag int) (int, error) {
	if n.Class != 0 || n.Tag != tag || n.IsCompound {
		return 0, errors.New("unexpected DER integer")
	}
	var v int
	var e error
	if tag == 10 {
		var x asn1.Enumerated
		_, e = asn1.Unmarshal(n.FullBytes, &x)
		v = int(x)
	} else {
		_, e = asn1.Unmarshal(n.FullBytes, &v)
	}
	if e != nil || v < 0 {
		return 0, errors.New("invalid DER integer")
	}
	return v, nil
}
func octets(n node) ([]byte, error) {
	if n.Class != 0 || n.Tag != 4 || n.IsCompound {
		return nil, errors.New("expected octets")
	}
	return n.Bytes, nil
}
func parseRecord(b, nonce []byte, level int, p Policy) (int, error) {
	n, e := decode(b)
	if e != nil {
		return 0, e
	}
	f, e := children(n, 16)
	if e != nil || len(f) != 8 {
		return 0, errors.New("invalid key description")
	}
	version, e := number(f[0], 2)
	if e != nil || version < 3 {
		return 0, errors.New("unsupported attestation version")
	}
	a, e := number(f[1], 10)
	if e != nil || a != level {
		return 0, errors.New("attestation security level mismatch")
	}
	k, e := number(f[2], 2)
	if e != nil || k < 3 {
		return 0, errors.New("unsupported keymaster version")
	}
	a, e = number(f[3], 10)
	if e != nil || a != level {
		return 0, errors.New("keymaster security level mismatch")
	}
	challenge, e := octets(f[4])
	if e != nil || !bytes.Equal(challenge, nonce) {
		return 0, errors.New("attestation challenge mismatch")
	}
	if _, e = octets(f[5]); e != nil {
		return 0, e
	}
	sw, e := authorizations(f[6])
	if e != nil {
		return 0, e
	}
	hw, e := authorizations(f[7])
	if e != nil {
		return 0, e
	}
	for tag := range sw {
		if _, ok := hw[tag]; ok {
			return 0, errors.New("duplicate cross-list authorization")
		}
	}
	for _, m := range []map[int]node{sw, hw} {
		for _, tag := range []int{503, 505, 506, 600} {
			if _, ok := m[tag]; ok {
				return 0, fmt.Errorf("forbidden authorization %d", tag)
			}
		}
	}
	for _, tag := range []int{1, 2, 3, 5, 10, 504, 702, 704} {
		if _, ok := sw[tag]; ok {
			return 0, fmt.Errorf("software security authorization %d", tag)
		}
	}
	for tag, want := range map[int]int{2: 3, 3: 256, 10: 1, 504: 2, 702: 0} {
		got, e := number(hw[tag], 2)
		if e != nil || got != want {
			return 0, fmt.Errorf("invalid hardware authorization %d", tag)
		}
	}
	for tag, want := range map[int]int{1: 2, 5: 4} {
		s, e := children(hw[tag], 17)
		if e != nil || len(s) != 1 {
			return 0, fmt.Errorf("invalid authorization set %d", tag)
		}
		got, e := number(s[0], 2)
		if e != nil || got != want {
			return 0, fmt.Errorf("incorrect authorization set %d", tag)
		}
	}
	rot, e := children(hw[704], 16)
	if e != nil || len(rot) != 4 {
		return 0, errors.New("missing verified boot root")
	}
	boot, e := octets(rot[0])
	if e != nil || len(boot) == 0 {
		return 0, errors.New("missing verified boot key")
	}
	var locked bool
	if _, e = asn1.Unmarshal(rot[1].FullBytes, &locked); e != nil || !locked {
		return 0, errors.New("device is not locked")
	}
	state, e := number(rot[2], 10)
	if e != nil || state != 0 {
		return 0, errors.New("unverified boot")
	}
	hash, e := octets(rot[3])
	if e != nil || len(hash) == 0 {
		return 0, errors.New("missing verified boot hash")
	}
	app, ok := sw[709]
	if !ok {
		app, ok = hw[709]
	}
	if !ok {
		return 0, errors.New("missing app identity")
	}
	if e = verifyApp(app, p); e != nil {
		return 0, e
	}
	return version, nil
}

func authorizations(n node) (map[int]node, error) {
	fields, e := children(n, 16)
	if e != nil {
		return nil, e
	}
	out := map[int]node{}
	last := -1
	for _, f := range fields {
		if f.Class != 2 || !f.IsCompound || f.Tag <= last {
			return nil, errors.New("duplicate, unordered or malformed authorization")
		}
		last = f.Tag
		inner, e := decode(f.Bytes)
		if e != nil {
			return nil, e
		}
		// Fail closed on new tags until their semantics have been reviewed. Metadata
		// is accepted with its declared ASN.1 type; security policy is checked above.
		var expected int
		switch f.Tag {
		case 1, 4, 5, 6, 203, 502:
			expected = 17
		case 2, 3, 8, 10, 200, 400, 401, 402, 405, 504, 505, 701, 702, 705, 706, 718, 719:
			expected = 2
		case 7, 202, 302, 303, 305, 503, 506, 507, 508, 509, 600, 703, 720, 721, 722:
			expected = 5
		case 601, 709, 710, 711, 712, 713, 714, 715, 716, 717, 723, 724:
			expected = 4
		case 704:
			expected = 16
		default:
			return nil, fmt.Errorf("unreviewed authorization tag %d", f.Tag)
		}
		if inner.Class != 0 || inner.Tag != expected || inner.IsCompound != (expected == 16 || expected == 17) {
			return nil, errors.New("authorization has incorrect DER type")
		}
		if expected == 2 {
			if _, e = number(inner, 2); e != nil {
				return nil, e
			}
		}
		if expected == 5 && len(inner.Bytes) != 0 {
			return nil, errors.New("invalid NULL authorization")
		}
		if expected == 17 {
			cs, e := children(inner, 17)
			if e != nil || len(cs) == 0 {
				return nil, errors.New("invalid authorization set")
			}
			var previous []byte
			for _, c := range cs {
				if _, e = number(c, 2); e != nil {
					return nil, e
				}
				if previous != nil && bytes.Compare(previous, c.FullBytes) >= 0 {
					return nil, errors.New("duplicate or unordered set value")
				}
				previous = c.FullBytes
			}
		}
		out[f.Tag] = inner
	}
	return out, nil
}
func verifyApp(n node, p Policy) error {
	b, e := octets(n)
	if e != nil {
		return e
	}
	root, e := decode(b)
	if e != nil {
		return e
	}
	fields, e := children(root, 16)
	if e != nil || len(fields) != 2 {
		return errors.New("malformed app identity")
	}
	packages, e := children(fields[0], 17)
	if e != nil || len(packages) != 1 {
		return errors.New("app package set must contain exactly the allowed package")
	}
	pkg, e := children(packages[0], 16)
	if e != nil || len(pkg) != 2 {
		return errors.New("malformed app package")
	}
	name, e := octets(pkg[0])
	if e != nil || string(name) != p.AppPackage {
		return errors.New("app package mismatch")
	}
	if _, e = number(pkg[1], 2); e != nil {
		return e
	}
	digests, e := children(fields[1], 17)
	if e != nil || len(digests) == 0 {
		return errors.New("missing signer digests")
	}
	var prev []byte
	for _, d := range digests {
		digest, e := octets(d)
		if e != nil || len(digest) != 32 {
			return errors.New("invalid signer digest")
		}
		if prev != nil && bytes.Compare(prev, d.FullBytes) >= 0 {
			return errors.New("duplicate or unordered signer digest")
		}
		prev = d.FullBytes
		allowed := false
		for _, a := range p.AppSignerDigests {
			if bytes.Equal(a, digest) {
				allowed = true
			}
		}
		if !allowed {
			return errors.New("signer digest is not allowlisted")
		}
	}
	return nil
}

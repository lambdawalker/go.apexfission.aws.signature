package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type configuration struct {
	bucket, table, receiptKey, issuer, scope, app, rootsPEM, rootsBucket, rootsKey, rootsHash string
	digests                                                                                   [][]byte
}

func readConfig(get func(string) string) (configuration, error) {
	c := configuration{bucket: get("DOCUMENT_BUCKET"), table: get("STATE_TABLE"), receiptKey: get("RECEIPT_KEY_ID"), issuer: get("JWT_ISSUER"), scope: get("JWT_SCOPE"), app: get("ALLOWED_APP_PACKAGE"), rootsPEM: get("GOOGLE_ROOTS_PEM"), rootsBucket: get("GOOGLE_ROOTS_BUCKET"), rootsKey: get("GOOGLE_ROOTS_KEY"), rootsHash: get("GOOGLE_ROOTS_SHA256")}
	for name, value := range map[string]string{"DOCUMENT_BUCKET": c.bucket, "STATE_TABLE": c.table, "RECEIPT_KEY_ID": c.receiptKey, "JWT_ISSUER": c.issuer, "ALLOWED_APP_PACKAGE": c.app} {
		if strings.TrimSpace(value) == "" {
			return c, fmt.Errorf("missing %s", name)
		}
	}
	u, e := url.Parse(c.issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, errors.New("JWT_ISSUER must be a trusted HTTPS issuer")
	}
	if c.scope == "" {
		c.scope = "signature:write"
	}
	for _, d := range strings.Split(get("ALLOWED_APP_DIGESTS"), ",") {
		b, e := hex.DecodeString(strings.TrimSpace(d))
		if e != nil || len(b) != 32 {
			return c, errors.New("ALLOWED_APP_DIGESTS requires SHA256 hex digests")
		}
		c.digests = append(c.digests, b)
	}
	if c.rootsPEM == "" {
		if c.rootsBucket == "" || c.rootsKey == "" {
			return c, errors.New("reviewed Google roots required")
		}
		h, e := hex.DecodeString(c.rootsHash)
		if e != nil || len(h) != 32 {
			return c, errors.New("Google roots object SHA256 pin required")
		}
	}
	return c, nil
}
func parseRoots(b []byte) (*x509.CertPool, error) {
	if len(b) == 0 || len(b) > 64*1024 {
		return nil, errors.New("Google root bundle size invalid")
	}
	pool := x509.NewCertPool()
	n := 0
	for len(bytes.TrimSpace(b)) > 0 {
		trimmed := bytes.TrimSpace(b)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("unexpected root PEM content")
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid root PEM")
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("invalid root CA")
		}
		pool.AddCert(c)
		n++
		b = rest
	}
	if n == 0 {
		return nil, errors.New("empty root pool")
	}
	return pool, nil
}

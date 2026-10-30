// Package api adapts API Gateway HTTP API events to the signature service.
// It trusts ONLY the API Gateway JWT authorizer context, never request headers.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aws/aws-lambda-go/events"
	"github.com/lambdawalker/go.apexfission.aws.signature/service"
	"io"
	"strings"
)

const MaxBody = 1024 * 1024

type Handler struct {
	Service *service.Service
	Issuer  string
	Scope   string
}

func response(status int, v any) events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(v)
	return events.APIGatewayV2HTTPResponse{StatusCode: status, Body: string(b), Headers: map[string]string{"content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff"}}
}
func failure(status int, msg string) events.APIGatewayV2HTTPResponse {
	return response(status, map[string]string{"error": msg})
}
func (h Handler) Handle(ctx context.Context, e events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	auth := e.RequestContext.Authorizer
	if h.Issuer == "" || h.Scope == "" || auth == nil || auth.JWT == nil || auth.JWT.Claims["iss"] != h.Issuer || auth.JWT.Claims["sub"] == "" {
		return failure(401, "unauthorized"), nil
	}
	scope := false
	for _, s := range auth.JWT.Scopes {
		if s == h.Scope {
			scope = true
		}
	}
	if !scope {
		return failure(403, "insufficient_scope"), nil
	}
	o := service.Identity{Issuer: h.Issuer, Subject: auth.JWT.Claims["sub"]}
	if len(e.Body) > MaxBody*2 {
		return failure(413, "request_too_large"), nil
	}
	body := e.Body
	if e.IsBase64Encoded {
		b, err := base64.StdEncoding.Strict().DecodeString(body)
		if err != nil {
			return failure(400, "invalid_json"), nil
		}
		body = string(b)
	}
	if len(body) > MaxBody {
		return failure(413, "request_too_large"), nil
	}
	var out any
	var err error
	switch e.RouteKey {
	case "POST /v1/challenges":
		var r service.ChallengeRequest
		if decode(body, &r) != nil {
			return failure(400, "invalid_json"), nil
		}
		if h.Service == nil {
			return failure(503, "unavailable"), nil
		}
		c, ce := h.Service.CreateChallenge(ctx, o, r)
		err = ce
		if err == nil {
			view := map[string]any{"challengeId": c.ID, "nonce": c.Nonce, "suite": c.Suite, "expiresAt": c.ExpiresAt, "issuer": c.Owner.Issuer, "subject": c.Owner.Subject}
			if c.Operation == "sign" {
				view["statement"] = c.StatementFor(c.KeyID).Encode()
			}
			out = view
		}
	case "POST /v1/registrations":
		var r service.RegisterRequest
		if decode(body, &r) != nil {
			return failure(400, "invalid_json"), nil
		}
		if h.Service == nil {
			return failure(503, "unavailable"), nil
		}
		out, err = h.Service.Register(ctx, o, r)
	case "POST /v1/signatures":
		var r service.SignRequest
		if decode(body, &r) != nil {
			return failure(400, "invalid_json"), nil
		}
		if h.Service == nil {
			return failure(503, "unavailable"), nil
		}
		out, err = h.Service.Sign(ctx, o, r)
	default:
		return failure(404, "not_found"), nil
	}
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalid):
			return failure(400, "verification_rejected"), nil
		case errors.Is(err, service.ErrNotFound):
			return failure(404, "not_found"), nil
		case errors.Is(err, service.ErrConflict):
			return failure(409, "expired_or_conflicting_operation"), nil
		default:
			return failure(503, "temporarily_unavailable_retry_same_request"), nil
		}
	}
	return response(200, out), nil
}

// decode rejects unknown fields, duplicate names (including nested ones), null,
// trailing JSON, and non-object top-level input before typed decoding.
func decode(body string, dst any) error {
	d := json.NewDecoder(strings.NewReader(body))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return errors.New("object required")
	}
	if e = object(d); e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	typed := json.NewDecoder(strings.NewReader(body))
	typed.DisallowUnknownFields()
	return typed.Decode(dst)
}
func object(d *json.Decoder) error {
	seen := map[string]bool{}
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return e
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return errors.New("duplicate JSON field")
		}
		seen[k] = true
		if e = value(d); e != nil {
			return e
		}
	}
	t, e := d.Token()
	if e != nil || t != json.Delim('}') {
		return errors.New("invalid object")
	}
	return nil
}
func value(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	switch t {
	case json.Delim('{'):
		return object(d)
	case json.Delim('['):
		for d.More() {
			if e = value(d); e != nil {
				return e
			}
		}
		t, e = d.Token()
		if e != nil || t != json.Delim(']') {
			return errors.New("invalid array")
		}
	}
	return nil
}

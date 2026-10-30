package api

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"testing"
)

func event(body string) events.APIGatewayV2HTTPRequest {
	return events.APIGatewayV2HTTPRequest{RouteKey: "POST /v1/challenges", Body: body, RequestContext: events.APIGatewayV2HTTPRequestContext{Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{Claims: map[string]string{"iss": "https://issuer", "sub": "alice"}, Scopes: []string{"signature:write"}}}}}
}
func TestRejectMissingOrWrongJWT(t *testing.T) {
	h := Handler{Issuer: "https://issuer", Scope: "signature:write"}
	for _, e := range []events.APIGatewayV2HTTPRequest{{}, event("{}")} {
		if e.RequestContext.Authorizer != nil {
			e.RequestContext.Authorizer.JWT.Claims["iss"] = "https://evil"
		}
		r, _ := h.Handle(context.Background(), e)
		if r.StatusCode != 401 {
			t.Fatalf("%d", r.StatusCode)
		}
	}
}
func TestRejectMissingScope(t *testing.T) {
	h := Handler{Issuer: "https://issuer", Scope: "signature:write"}
	e := event("{}")
	e.RequestContext.Authorizer.JWT.Scopes = nil
	r, _ := h.Handle(context.Background(), e)
	if r.StatusCode != 403 {
		t.Fatal(r.StatusCode)
	}
}
func TestStrictDecode(t *testing.T) {
	for _, body := range []string{`{"x":1,"x":2}`, `{"nested":{"x":1,"x":2}}`, `{} {}`, `{"unknown":1}`, `null`, `[]`} {
		var v struct{}
		if decode(body, &v) == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	var v struct {
		X int `json:"x"`
	}
	if err := decode(`{"x":1}`, &v); err != nil || v.X != 1 {
		t.Fatal(err)
	}
}
func TestRejectEncodedAndOversizeBody(t *testing.T) {
	h := Handler{Issuer: "https://issuer", Scope: "signature:write"}
	e := event("bad base64")
	e.IsBase64Encoded = true
	r, _ := h.Handle(context.Background(), e)
	if r.StatusCode != 400 {
		t.Fatal(r.StatusCode)
	}
	e = event(string(make([]byte, MaxBody+1)))
	r, _ = h.Handle(context.Background(), e)
	if r.StatusCode != 413 {
		t.Fatal(r.StatusCode)
	}
	var v map[string]any
	if json.Unmarshal([]byte(r.Body), &v) != nil {
		t.Fatal("not JSON")
	}
}

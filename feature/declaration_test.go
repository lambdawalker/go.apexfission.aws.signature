package feature

import (
	composer "github.com/lambdawalker/go.infra.composer"
	"testing"
)

func provider(test bool) *composer.Feature {
	return &composer.Feature{ID: "host", Offerings: []composer.Offering{{ID: "jwt", Contract: IdentityContract(), TestOnly: test, Values: map[string]composer.Value{"issuer": composer.Literal("https://example.com"), "audience": composer.Literal("client"), "scope": composer.Literal("sign")}}}}
}
func TestCompositionRequiresIdentity(t *testing.T) {
	if _, err := composer.NewApplication("test", Declare("signature")).Plan(composer.Environment{Name: "dev"}); err == nil {
		t.Fatal("missing identity accepted")
	}
	app := composer.NewApplication("test", provider(false), Declare("signature"))
	if err := app.Inject("signature", IdentityRequirement, "host", "jwt"); err != nil {
		t.Fatal(err)
	}
	plan, err := app.Plan(composer.Environment{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Resources()) != 1 || plan.Resources()[0].Kind != Kind {
		t.Fatal("wrong plan")
	}
}
func TestProductionRejectsTestIdentity(t *testing.T) {
	if _, err := composer.NewApplication("test", provider(true), Declare("signature")).Plan(composer.Environment{Name: "prod"}); err == nil {
		t.Fatal("test identity accepted")
	}
}
func TestContractMismatchRejected(t *testing.T) {
	p := provider(false)
	p.Offerings[0].Contract.Major = 2
	if _, err := composer.NewApplication("test", p, Declare("signature")).Plan(composer.Environment{Name: "dev"}); err == nil {
		t.Fatal("incompatible contract accepted")
	}
}

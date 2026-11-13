package main

import (
	feature "github.com/lambdawalker/go.apexfission.aws.signature/feature"
	infrastructure "github.com/lambdawalker/go.apexfission.aws.signature/infrastructure"
	composer "github.com/lambdawalker/go.infra.composer"
	adapter "github.com/lambdawalker/go.infra.composer/adapters/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func deploy(ctx *pulumi.Context) error {
	cfg := config.New(ctx, "")
	identity := &composer.Feature{ID: "identity", Offerings: []composer.Offering{{ID: "jwt", Contract: feature.IdentityContract(), Values: map[string]composer.Value{
		"issuer": composer.Literal(cfg.Require("jwtIssuer")), "audience": composer.Literal(cfg.Require("jwtAudience")), "scope": composer.Literal(cfg.Require("jwtScope")),
	}}}}
	app := composer.NewApplication("sworn-ink", identity, feature.Declare("signature"))
	if err := app.Inject("signature", feature.IdentityRequirement, "identity", "jwt"); err != nil {
		return err
	}
	plan, err := app.Plan(composer.Environment{Name: ctx.Stack(), Region: config.Require(ctx, "aws:region"), Account: cfg.Require("awsAccount")})
	if err != nil {
		return err
	}
	factory := infrastructure.Factory(cfg, infrastructure.Options{})
	result, err := adapter.Execute(ctx, plan, adapter.Registry{feature.Kind: factory})
	if err != nil {
		return err
	}
	outputs := result.Resources["signature.backend"].Outputs
	for native, key := range map[string]string{"apiURL": "api_url", "bucket": "bucket", "stateTable": "state_table", "receiptKey": "receipt_key"} {
		ctx.Export(native, outputs[key])
	}
	return nil
}
func main() { pulumi.Run(deploy) }

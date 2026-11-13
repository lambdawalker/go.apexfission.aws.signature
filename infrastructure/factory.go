package infrastructure

import (
	"fmt"
	adapter "github.com/lambdawalker/go.infra.composer/adapters/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

// Factory constructs the bounded native registry entry. Configuration is scoped
// by the host (e.g. config.New(ctx,"signature")); no host package is imported.
// Register only one signature backend per stack with this Options value.
func Factory(cfg *config.Config, options Options) adapter.Factory {
	return func(ctx *pulumi.Context, _ string, inputs pulumi.Map, resourceOptions ...pulumi.ResourceOption) (adapter.Registered, error) {
		opts := options
		fields := map[string]pulumi.StringOutput{}
		for _, key := range []string{"issuer", "audience", "scope"} {
			input, ok := inputs[key]
			if !ok {
				return adapter.Registered{}, fmt.Errorf("missing JWT input %s", key)
			}
			fields[key] = pulumi.ToOutput(input).ApplyT(func(v any) (string, error) {
				s, ok := v.(string)
				if !ok {
					return "", fmt.Errorf("JWT input must be string")
				}
				return s, nil
			}).(pulumi.StringOutput)
		}
		opts.Issuer, opts.Audience, opts.Scope = fields["issuer"], fields["audience"], fields["scope"]
		opts.ResourceOptions = append(append([]pulumi.ResourceOption{}, options.ResourceOptions...), resourceOptions...)
		deployed, err := Deploy(ctx, cfg, opts)
		if err != nil {
			return adapter.Registered{}, err
		}
		return adapter.Registered{Resource: deployed.Resource, Outputs: map[string]pulumi.Output{"api_url": deployed.APIURL, "bucket": deployed.Bucket, "state_table": deployed.StateTable, "receipt_key": deployed.ReceiptKey}}, nil
	}
}

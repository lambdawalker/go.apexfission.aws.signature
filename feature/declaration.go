// Package feature declares the signature backend without cloud dependencies.
package feature

import composer "github.com/lambdawalker/go.infra.composer"

const Kind = "apexfission:signature:Backend"
const IdentityRequirement = "jwt_identity"

// IdentityContract describes deployment trust configuration, not user identity.
// The host explicitly maps its auth offering to these access-token settings.
func IdentityContract() composer.Contract {
	return composer.Contract{ID: "identity.jwt-verifier", Major: 1, Fields: map[string]composer.Field{
		"issuer": {Type: composer.String}, "audience": {Type: composer.String}, "scope": {Type: composer.String},
	}}
}
func APIContract() composer.Contract {
	return composer.Contract{ID: "signature.api", Major: 1, Fields: map[string]composer.Field{"api_url": {Type: composer.String}}}
}
func Declare(id string) *composer.Feature {
	inputs := map[string]composer.Value{}
	for key := range IdentityContract().Fields {
		inputs[key] = composer.RequirementRef(id, IdentityRequirement, key)
	}
	outputs := map[string]composer.Field{}
	for _, key := range []string{"api_url", "bucket", "state_table", "receipt_key"} {
		outputs[key] = composer.Field{Type: composer.String}
	}
	return &composer.Feature{ID: id, Source: composer.Origin(),
		Requirements: []composer.Requirement{{ID: IdentityRequirement, Contract: IdentityContract(), Source: composer.Origin()}},
		Resources:    []composer.Resource{{ID: "backend", Kind: Kind, Source: composer.Origin(), Inputs: inputs, Outputs: outputs}},
		Offerings:    []composer.Offering{{ID: "api", Contract: APIContract(), Values: map[string]composer.Value{"api_url": composer.ResourceRef(id+".backend", "api_url")}}},
	}
}

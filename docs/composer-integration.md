# Composer and Attestra integration

The root `feature` package exposes `Declare(id)`, `Kind`, `IdentityContract()` and `APIContract()`. `artifacts.Lambdas()` lists `signature-api`, built from `github.com/lambdawalker/go.apexfission.aws.signature/cmd/api`. The separate `infrastructure` module exposes `Deploy` and a bounded Composer `Factory`. No Attestra source or live deployment is changed here.

Signature requires `identity.jwt-verifier` major 1 with string fields `issuer`, `audience`, `scope`. It offers `signature.api` major 1 with `api_url`. No default identity provider exists. Production rejects test-only providers. The host must explicitly map actual access-token settings; Attestra's `auth.identity` contract is not automatically interchangeable.

## Host steps

1. Pin root and infrastructure modules to the same merged implementation commit. Local replacements are for development; downstream Go consumers ignore them. Add `feature.Declare("signature")` through Attestra's additional feature argument.
2. Register an application-owned offering implementing `feature.IdentityContract()`. Explicitly call `app.Inject("signature", feature.IdentityRequirement, "signature-identity", "jwt")` before planning. Verify the auth backend actually issues the required access-token audience/scope. Do not substitute email or an ID-token audience. Exact issuer/subject remains the account identity.
3. Build the manifest package for linux/arm64 into a ZIP containing executable `bootstrap` at its root. Retain the command as a host Go tool dependency, following Attestra's existing builder. Pass its archive path as `Options.Artifact`.
4. Use `config.New(ctx,"signature")` for feature-specific settings: `appPackage`, `appDigests`, `googleRootsPEM`, `awsAccount`, optional `logRetentionDays`. Region comes from `aws:region`.
5. Add `feature.Kind: infrastructure.Factory(signatureConfig, infrastructure.Options{Prefix:"signature-", Artifact:archivePath, BoundaryARN:reviewedBoundaryARN})` to the bounded native registry. To apply Attestra's feature ownership labels, wrap the factory and pass the context returned by `awslabels.ForFeature(ctx,"signature")` to it. The factory forwards Composer resource dependency and secret options to every child.
6. After normal readiness checks, publish the resulting `api_url` through application discovery. Signature owns a separate HTTP API with three POST routes and a JWT authorizer.

The factory accepts preview-unknown native Pulumi outputs. Resolved issuer must be HTTPS and audience/scope nonempty; failures stop Pulumi. Reviewed attestation roots, app digests, artifact readability and resource identity are checked before resource constructors. Native tests do not establish live token/IAM compatibility.

## Ownership and migration

Signature owns its DynamoDB table, private versioned SSE-KMS evidence bucket, storage/receipt keys, root object, Lambda/IAM/logging, HTTP API and JWT authorizer. The host must preprovision a reviewed permissions boundary for those exact resources and pass `BoundaryARN`. The default is the standalone project/environment boundary. Do not substitute Attestra's shared runtime table or enroll evidence in generic account reset/deletion without a retention decision.

Standalone deployment uses the same factory with an empty prefix. Existing logical names, physical names and exports (`apiURL`, `bucket`, `stateTable`, `receiptKey`) are preserved; launchers, setup/vault and build cache remain supported. Go 1.27.3+ is required for the pinned Composer adapter.

Use a nonempty logical prefix in Attestra to avoid generic resource-name collisions. Table/function/role physical names include it. The evidence bucket keeps account/region/environment naming: only one signature instance per such scope is supported. A second instance needs a separately reviewed naming change.

A different Pulumi project/state is a migration boundary. This change does not transfer registrations, evidence, keys, API endpoints or state to Attestra. Review imports/aliases and preserve existing keys and exact issuer/subject identities before moving a live system. No provisioning, workflow dispatch or state changes are required for verification.

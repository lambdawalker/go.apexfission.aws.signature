# AWS resource inventory and operating contract

The source describes a deployable design; no live infrastructure or acceptance is confirmed. For executable deployment commands, configuration persistence, vault recovery and confirmation behavior see [deployment tooling](https://github.com/lambdawalker/go.apexfission.aws.signature/blob/feat/sworn-ink-signatures/docs/deployment.md). Build/preview/status do not imply permission to deploy. AWS environment/account/region, S3 state and operator credentials must be selected explicitly.

## Resource ownership

- API Gateway HTTP API: three POST routes, JWT issuer/audience authorizer and required scope, Lambda proxy integration and stage throttling.
- Lambda: ARM64 `provided.al2023` runtime using the compiled `bootstrap`, explicit timeout/memory, role limited to service dependencies and logs.
- DynamoDB: on-demand table with `pk`, conditional challenge/key state, TTL cleanup, point-in-time recovery and KMS encryption.
- Evidence S3: private versioned bucket, public access blocked, TLS-only policy, default SSE-KMS encryption and deterministic create-only evidence objects. Force deletion is disabled. Versioning does not imply compliance object lock.
- KMS storage key: encryption for evidence and state; rotation enabled. KMS receipt key: separate asymmetric P-256 signing key, not an encryption key.
- IAM/CloudWatch: scoped table/object/KMS permissions and log group retention. Reviewed root bundles may use a separate protected S3 object with read permission. No Cognito directory, email service or built-in TSA is provisioned.

## Runtime configuration

Required settings are `DOCUMENT_BUCKET`, `STATE_TABLE`, `RECEIPT_KEY_ID`, `JWT_ISSUER`, `ALLOWED_APP_PACKAGE`, `ALLOWED_APP_DIGESTS`. Digests are comma-separated SHA-256 hex of app signing certificates. `JWT_SCOPE` defaults to `signature:write`; it must match the Gateway route scope. JWT audience is enforced by Gateway configuration, not chosen by client JSON.

Supply reviewed roots through `GOOGLE_ROOTS_PEM`, or through `GOOGLE_ROOTS_BUCKET`, `GOOGLE_ROOTS_KEY` and `GOOGLE_ROOTS_SHA256` together when inline PEM is absent. The object bytes must match the pinned SHA-256. The bundle is bounded to 64 KiB and must parse as valid CA certificates. The S3 path/pin is operator configuration; do not obtain trust anchors from an untrusted request. `AWS_REGION` and credentials use the AWS SDK chain; local deployment uses SSO and CI uses scoped OIDC rather than committed keys.

## Operations and retention

Monitor Lambda errors/timeouts, throttling, conditional conflicts, evidence write failures, KMS errors and Google revocation connectivity. Alarm configuration and live incident thresholds require operator setup. Keep document/token data out of logs. Choose retention intentionally and test authorized restoration of S3 versions and DynamoDB point-in-time backups; encrypted storage recovery also requires surviving KMS keys and access policies. Do not delete or rotate receipt keys without retaining a verification strategy for existing receipts.

Before production acceptance, exercise real token/scope denials, cross-account rejection, supported device registration and biometric cancellation/enrollment change, revoked/stale attestation failure, exact retry after each persistence boundary, evidence reconstruction and KMS verification. Observe private storage, regional/account isolation, recovery and policy retention in the selected AWS environment. None of those cloud/device checks is claimed by local unit tests.

## Deployment identity and permission boundaries

Before selecting or operating a Pulumi stack, the deployment tool downloads authoritative encrypted stack YAML and secrets-provider metadata from `DEPLOY_BACKEND/ENV/config/Pulumi.ENV.yaml`, even when a local YAML already exists. Downloads use a temporary file and replace local configuration only after a successful, nonempty restore. A failed restore preserves the local file and stops; it does not permit local fallback or secret regeneration. New setup is possible only after an explicit missing-object response, no local YAML, and `--action setup --approve`; an existing stack without its remote encrypted configuration requires recovery.

Before preview/status/recovery, the tool checks `aws:region`, project `awsAccount` and the provider `aws:allowedAccountIds` against the selected target. The allowlist must contain exactly that one account. Setup/reconfiguration writes that provider restriction and validates the resulting configuration. Immediately before applying the saved plan, the tool rechecks both STS account/role and provider target settings. A valid AWS session alone does not establish a safe Pulumi region or target.

A separately privileged bootstrap identity reviews `--action oidc-plan` and, only when explicitly authorized, runs `--action oidc-setup --approve`. The trust policy is restricted to the GitHub Actions issuer, `aud=sts.amazonaws.com` and exact `repo:OWNER/REPO:environment:ENV` subject. Bootstrap creates or verifies the fixed runtime boundary `arn:aws:iam::ACCOUNT:policy/sworn-ink-ENV-runtime-boundary`; the Pulumi Lambda role always references it. The normal deployment role can create that runtime role only with this boundary and cannot replace/remove the boundary or alter its policy versions. Broader inline runtime permissions remain capped by the bootstrap-owned boundary for this environment's table, evidence/root objects, tagged KMS keys and logs.

API creation requires project/environment request tags; subsequent API management is conditioned on matching resource tags. Where AWS does not evaluate the required tag conditions for a descendant operation, deployment fails closed rather than broadening access to every API in the region. DynamoDB KMS grant creation is restricted to environment-tagged keys and `kms:GrantIsForAWSResource=true`. These are reviewed code constraints, not live IAM acceptance evidence; validate provider behavior in an isolated account before production and keep bootstrap privileges separate from deployment credentials.

## Documentation hosting

The manual GitHub Pages workflow only accepts trusted main. It builds these guides with read-only repository access, then grants Pages and OIDC permissions only to the publish job. It does not run an AWS deployment, package publication or release action. Select Pages as the repository hosting provider and use the protected `github-pages` environment before explicitly dispatching. No hosted URL is claimed until the repository workflow actually succeeds.

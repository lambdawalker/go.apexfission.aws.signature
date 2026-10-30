# Deploying the signature backend

This project deploys one Backend component: API Gateway HTTP API, Lambda, DynamoDB, private versioned SSE-KMS S3, receipt/storage KMS keys and CloudWatch logs. There is no admin/index, DNS, SES or Cognito. Building/testing does not deploy anything. Real AWS, GitHub, Windows-terminal and hardware-device acceptance remain operator checks.

## Prerequisites and inputs

Go 1.26+, AWS CLI v2, Pulumi 3.200+, and GitHub CLI v2 for optional GitHub setup must be on PATH. CI pins Go 1.26.6 and Pulumi 3.264.0; the AWS provider is pinned to 7.44.0. Only the commercial AWS partition is currently supported. Set up an IAM Identity Center profile with `aws configure sso`; the wizard validates STS and invokes `aws sso login --profile PROFILE` for an expired interactive session. CI uses OIDC. Long-lived credentials are never requested.

The root `deploy.sh` and `deploy.bat` resolve the repository independently of the caller's directory and invoke the same Go program. Select the environment first: dev, qa, prod or a validated lowercase custom name up to 32 characters. No implicit production target exists. Saved settings are scoped to `sworn-ink/ENV` under the platform configuration directory. Explicit environment variables override saved answers. The environment operation lock serializes local runs; stale locks are never automatically stolen.

| Input | Meaning |
| --- | --- |
| `AWS_PROFILE` | Existing interactive SSO profile |
| `DEPLOY_ACCOUNT`, `AWS_REGION` | Exact target account/region; STS account must match |
| `DEPLOY_BACKEND` | Existing bucket and dedicated prefix: `s3://BUCKET/PROJECT` |
| `DEPLOY_REPOSITORY`, `DEPLOY_ROLE_ARN` | GitHub owner/repository and environment OIDC role |
| `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_SCOPE` | Reviewed HTTPS issuer, access audience and scope |
| `ALLOWED_APP_PACKAGE`, `ALLOWED_APP_DIGESTS` | Package and comma separated signer SHA256 hex digests |
| `GOOGLE_ROOTS_PEM` | Reviewed Google hardware-attestation root CA PEM bundle |
| `PULUMI_CONFIG_PASSPHRASE` | Required in CI; interactive runs can use encrypted vault |

Use placeholders in documentation and never put secrets in Git, arguments or logs. Public root certificates and JWT trust settings are configuration, not credentials. Root certificate syntax is validated, but operators must review the actual root trust selection.

## Setup, preview and apply

1. Separately provision/select an existing private S3 state bucket. The tool checks expected owner, region, enabled versioning, all public access blocks and encryption. It does not create a bucket. Operators need bucket metadata/list access and state-prefix read/write/delete access. SSE-KMS state buckets also need their own key grant.
2. Set the inputs above. On first setup all JWT/application/root trust inputs are required. Run `./deploy.sh --environment dev --action setup --approve` (or `deploy.bat`). Approval here permits a new Pulumi stack only after the operator has checked that its identity does not belong to existing infrastructure. Setup does not apply AWS resources.
3. Interactive first setup captures a hidden confirmed vault password (minimum 12 characters) and a separate confirmed Pulumi passphrase. Use the original passphrase for an existing stack. The private versioned vault uses PBKDF2-HMAC-SHA256 (600,000 iterations), random salt and AES-256-GCM with random nonce. Wrong passwords/corruption fail without overwriting it. Keep vault/passphrase backups separately; its unlock password is never stored.
4. `--action build` creates `build/bootstrap.zip`. `--action preview` builds, refreshes state, saves a Pulumi plan and prints its diff. Neither action applies changes.
5. `--action deploy` performs the same successful preview first, then asks: `Deploy the previewed changes? [Y/n] Continuing in 5 seconds; press n or Ctrl+C to cancel.` Enter/yes proceeds immediately, silence for five seconds proceeds, and n/Escape/Ctrl+C/EOF/input errors cancel. This countdown exists only for an explicitly selected interactive deploy. Before applying the saved plan STS account and role are checked again. CI requires `--noninteractive --approve`; EOF never authorizes it.

State lives below `DEPLOY_BACKEND/ENV`. Pulumi maintains multiple checkpoint/lock objects; do not edit one state file. S3 encryption, Pulumi secret encryption and local-vault encryption serve different purposes. The passphrase does not authenticate to S3 or encrypt every state field. Protect all state with IAM. Authoritative stack YAML and secrets-provider metadata are backed up at `DEPLOY_BACKEND/ENV/config/Pulumi.ENV.yaml`, and restored on fresh checkouts before stack selection. Missing YAML is not permission to regenerate keys or secrets. Reconfiguration requires explicit complete values and preserves stack identity.

## Runtime inventory

| Resource | Behavior |
| --- | --- |
| HTTP API | POST `/v1/challenges`, `/v1/registrations`, `/v1/signatures`; external JWT issuer/audience and required scope on all routes |
| Lambda | `provided.al2023`, arm64, executable `bootstrap` ZIP, 256 MiB, 30-second timeout |
| DynamoDB | On-demand, string `pk`, point-in-time recovery, SSE-KMS; cleanup TTL on `ttlAt`, separate from service authorization expiry |
| S3 | Versioned, SSE-KMS, all public access blocked, TLS-only; no force destroy or compliance retention |
| Receipt KMS | Separate `ECC_NIST_P256`, `SIGN_VERIFY`; runtime signs using `ECDSA_SHA_256` |
| Storage KMS | Symmetric rotating encryption key for table/evidence |
| CloudWatch | Explicit Lambda log group; default 30 days, configurable `logRetentionDays` |

Lambda IAM permits table GetItem/PutItem/UpdateItem (transactions authorize underlying item actions), GetObject/PutObject under `evidence/*`, read-only exact `config/google-roots.pem`, storage-key data-key/decrypt, receipt-key Sign/GetPublicKey, and its own log stream writes. It cannot list evidence or modify roots.

Runtime variables: `DOCUMENT_BUCKET`, `STATE_TABLE`, `RECEIPT_KEY_ID`, `ALLOWED_APP_PACKAGE`, `ALLOWED_APP_DIGESTS`, `JWT_ISSUER`, `JWT_SCOPE`, `GOOGLE_ROOTS_BUCKET`, `GOOGLE_ROOTS_KEY`, `GOOGLE_ROOTS_SHA256`. The root bundle is an encrypted object pinned by SHA256 before parsing; this avoids Lambda's aggregate 4 KiB environment limit. Local initialization may use `GOOGLE_ROOTS_PEM` directly. The HTTP handler limits decoded documents to 512 KiB; API Gateway's larger transport limit does not replace application bounds.

Lambda, table and runtime role names are deterministic per environment; bucket names include account/region. Changing environment/account/region changes resource identity. Do not use reconfiguration as a migration. KMS deletion windows are 30 days; recover evidence, data and encryption/signing keys together.

## OIDC and GitHub

No setup is run merely to validate code. Run `--action oidc-plan` to review emitted JSON, then separately authorize `--action oidc-setup --approve` with a bootstrap identity. It checks the AWS account, creates a missing GitHub OIDC provider and environment deployment role. Trust is exact `repo:OWNER/REPO:environment:ENV` and `aud=sts.amazonaws.com`. Existing incompatible trust/policies fail for review; unrelated policies are preserved and require separate review. Set `DEPLOY_ROLE_ARN=arn:aws:iam::ACCOUNT:role/sworn-ink-ENV-github-deploy` afterward. The bootstrap identity needs IAM provider/role inspection and creation plus PutRolePolicy; the deployment role does not bootstrap itself.

The generated deployment policy is reviewable code, not a claim of live IAM acceptance. Resource names scope most permissions. CreateKey and DescribeLogGroups require wildcard resources; key creation is restricted by request tags, later key management by project/environment resource tags. API Gateway management uses regional API paths because IDs are assigned at creation. Stricter organizations should preprovision APIs or use permission boundaries. An existing SSE-KMS state bucket requires an extra exact key grant. Provider read permissions must be validated in an isolated account before production.

Run `--action github-plan` to inspect differences, then `--action github-setup --approve`. It verifies authenticated GitHub identity and repository, queries existing environments before writes, creates only missing environments, and preserves protection rules/reviewers/branch restrictions. GitHub operators need repository environment administration and variable/secret management permissions. Newly created environments have GitHub defaults: review required reviewers and deployment branch restrictions before production. Permission failures remain incomplete and print a manual environment-settings URL.

Managed environment variables are `DEPLOY_ACCOUNT`, `AWS_REGION`, `DEPLOY_BACKEND`, `DEPLOY_ROLE_ARN`, `DEPLOY_REPOSITORY`, `DEPLOY_ENVIRONMENT`, `DEPLOY_COMPONENT=Backend`, `DEPLOY_CONFIG_SHA256`. The required secret is `PULUMI_CONFIG_PASSPHRASE`. Missing secrets are read from process environment or unlocked vault and sent to `gh secret set` through stdin. Existing names are preserved; secret values cannot be read back. Rotate deliberately using `gh secret set PULUMI_CONFIG_PASSPHRASE --repo OWNER/REPO --env ENV` with stdin, and coordinate local vault/Pulumi encryption recovery.

Every run reads actual managed variables and secret-name inventory; matching markers cannot hide a deleted variable/secret. A marker proves only managed configuration comparison, not independent IAM readiness, secret values or protection settings. Recheck those after external changes. Local operation locks serialize setup and Actions concurrency serializes deployments for the same environment.

The manual workflow is `.github/workflows/deploy.yml`, under `https://github.com/OWNER/REPO/actions/workflows/deploy.yml`. Choose the exact protected environment, preview/deploy, and explicit deploy approval. It uses OIDC, minimal workflow permissions, complete inputs and the same program. Setup never dispatches it. This project has only Backend, so no irrelevant Admin/index/All choice is offered.

## Cache and recovery

Canonical sorted JSON fingerprints cover actual source content, module metadata, scope, Go version, linux/arm64 target, flags and ZIP recipe. Outputs are excluded. Cached ZIP bytes have an independent SHA256; missing/corrupt records and tampering rebuild. `--force-rebuild` bypasses reuse. ZIP mode/time are deterministic; Pulumi receives actual ZIP SHA256 in AWS base64 format. Artifact reuse never skips refresh/preview. Repository-external local module replacements are unsupported; vendor dependencies into the repository first.

After interruption rerun the same command. Cache publication is atomic, failed updates do not publish success receipts, and locks are never stolen. `--action status`/`recovery` print stack outputs only, not live health. Preserve state-bucket versions, authoritative YAML, vault and both passwords. Do not regenerate keys, reset state, destroy buckets or switch environments to recover. Teardown is intentionally absent.

Live acceptance: verify actual IAM/resource inventory, JWT missing/wrong issuer/audience/scope rejection, real StrongBox/TEE registration, expired/replayed/cross-account rejection, evidence exact retry recovery, root hash pinning, fresh revocation failure, encryption/TLS denial, and backup restoration in isolation. There is no anonymous health endpoint. Independent RFC3161 timestamps require a real separately configured provider; absence remains unavailable.

Local checks: `cd infra && go test ./...`, `cd cmd/deploy && go test ./...`, and root runtime tests. Mocked Pulumi and fake CLI tests cover resources, vault integrity, cancellation, build reuse/tamper detection and configuration drift without cloud calls. Remaining tooling limits: no state-bucket bootstrap, migration import/export, automated vault/password rotation, live health or repository-external replacement cache. GitHub secret values/independent role policies/protection rules require operator verification. Restore a vault in its original scope instead of renaming it across environments.

The OIDC bootstrap also creates and verifies the fixed runtime permissions boundary `arn:aws:iam::ACCOUNT:policy/sworn-ink-ENV-runtime-boundary`. The Pulumi runtime role always references it. Deployment-role CreateRole requires this exact boundary, and the deployer has no permission to replace/remove the boundary or create/set/delete boundary policy versions. The boundary caps runtime authority to this environment's table, evidence/root object, tagged keys and logs even if a changed inline role policy is broader. Only the separately privileged bootstrap operator can create/modify it. `kms:CreateGrant` for DynamoDB is restricted to tagged environment keys with `kms:GrantIsForAWSResource=true`.

API Gateway management is additionally restricted by Project/Environment resource tags and API creation request tags. Child-resource tag-condition evaluation has not been confirmed in a live AWS account; those operations deliberately fail closed if AWS does not expose inherited API tags for them. Do not replace the policy with unrestricted `/apis/*` writes to make a failing deployment pass. A reviewed explicit API-ID allowlist or separately preprovisioned API is the fallback before production readiness.

Local SSO deployments can skip GitHub entirely: separately run `--action boundary-plan`, review the emitted runtime boundary, then authorize `--action boundary-setup --approve` with the bootstrap operator. These commands require account, region and environment, and do not require a repository, OIDC role or state bucket. Existing incompatible boundary policies fail for privileged review. Configure the normal S3 stack with `--action setup` afterward and use preview/deploy locally. OIDC setup reuses this same boundary bootstrap.

#!/usr/bin/env sh
set -eu
DEPLOY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DEPLOY_ROOT/cmd/deploy"
exec go run . "$@"

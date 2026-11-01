#!/usr/bin/env bash
# Run the host-neutral checks in a Debian trixie container.
#   tools/pi-lab/run-checks.sh            # docker or podman, if present
#   RUNNER=nerdctl tools/pi-lab/run-checks.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
RUNNER="${RUNNER:-$(command -v docker || command -v podman || command -v nerdctl || true)}"
[[ -n "$RUNNER" ]] || { echo "no container runtime; try: limactl shell pi-lab" >&2; exit 1; }
"$RUNNER" build -f tools/pi-lab/Containerfile -t mockmfi-lab .
"$RUNNER" run --rm mockmfi-lab

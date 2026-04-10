#!/usr/bin/env bash
# Run the full Docker test matrix locally.
# Usage: bash tests/docker/run_matrix.sh [--no-build]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKERFILE="$ROOT/tests/docker/Dockerfile.test"

PYTHON_VERSIONS=("3.9" "3.12")
GITLEAKS_OPTS=("false" "true")

failures=0
results=()

build_and_run() {
    local py="$1"
    local gl="$2"
    local tag="leak-guard-test:py${py}-gl${gl}"
    local label="python=${py} gitleaks=${gl}"

    echo ""
    echo "══════════════════════════════════════════"
    echo "  Matrix: ${label}"
    echo "══════════════════════════════════════════"

    docker build \
        --build-arg "PYTHON_VERSION=${py}" \
        --build-arg "INSTALL_GITLEAKS=${gl}" \
        -f "$DOCKERFILE" \
        -t "$tag" \
        "$ROOT" \
        --quiet

    if docker run --rm "$tag"; then
        results+=("PASS  ${label}")
    else
        results+=("FAIL  ${label}")
        failures=$((failures + 1))
    fi
}

for py in "${PYTHON_VERSIONS[@]}"; do
    for gl in "${GITLEAKS_OPTS[@]}"; do
        build_and_run "$py" "$gl"
    done
done

echo ""
echo "══════════════════════════════════════════"
echo "  Matrix Results"
echo "══════════════════════════════════════════"
for r in "${results[@]}"; do
    echo "  $r"
done
echo ""

if [ "$failures" -eq 0 ]; then
    echo "All matrix runs passed."
    exit 0
else
    echo "${failures} matrix run(s) failed."
    exit 1
fi

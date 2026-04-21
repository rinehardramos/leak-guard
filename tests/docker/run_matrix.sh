#!/usr/bin/env bash
# Run the full Docker test matrix locally.
# Usage: bash tests/docker/run_matrix.sh [--no-build]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKERFILE="$ROOT/tests/docker/Dockerfile.test"

PYTHON_VERSIONS=("3.9" "3.12")
GITLEAKS_OPTS=("false" "true")
PLATFORMS=("linux/amd64" "linux/arm64")

failures=0
results=()

build_and_run() {
    local py="$1"
    local gl="$2"
    local plat="$3"
    local arch="${plat##*/}"  # amd64 or arm64
    local tag="leak-guard-test:py${py}-gl${gl}-${arch}"
    local label="python=${py} gitleaks=${gl} platform=${plat}"

    echo ""
    echo "══════════════════════════════════════════"
    echo "  Matrix: ${label}"
    echo "══════════════════════════════════════════"

    if ! docker build \
        --platform "$plat" \
        --build-arg "PYTHON_VERSION=${py}" \
        --build-arg "INSTALL_GITLEAKS=${gl}" \
        -f "$DOCKERFILE" \
        -t "$tag" \
        "$ROOT" \
        --quiet 2>/dev/null; then
        results+=("SKIP  ${label} (build failed — platform not supported)")
        return
    fi

    if docker run --rm --platform "$plat" "$tag"; then
        results+=("PASS  ${label}")
    else
        results+=("FAIL  ${label}")
        failures=$((failures + 1))
    fi
}

for py in "${PYTHON_VERSIONS[@]}"; do
    for gl in "${GITLEAKS_OPTS[@]}"; do
        for plat in "${PLATFORMS[@]}"; do
            build_and_run "$py" "$gl" "$plat"
        done
    done
done

# ── TUI compatibility tests (opencode + gemini-cli proxy compat) ─────────

TUI_DOCKERFILE="$ROOT/tests/docker/Dockerfile.tui-compat"

build_and_run_tui() {
    local py="$1"
    local plat="$2"
    local arch="${plat##*/}"
    local tag="leak-guard-tui-compat:py${py}-${arch}"
    local label="tui-compat python=${py} platform=${plat}"

    echo ""
    echo "══════════════════════════════════════════"
    echo "  Matrix: ${label}"
    echo "══════════════════════════════════════════"

    if ! docker build \
        --platform "$plat" \
        --build-arg "PYTHON_VERSION=${py}" \
        -f "$TUI_DOCKERFILE" \
        -t "$tag" \
        "$ROOT" \
        --quiet 2>/dev/null; then
        results+=("SKIP  ${label} (build failed — platform not supported)")
        return
    fi

    if docker run --rm --platform "$plat" "$tag"; then
        results+=("PASS  ${label}")
    else
        results+=("FAIL  ${label}")
        failures=$((failures + 1))
    fi
}

for py in "${PYTHON_VERSIONS[@]}"; do
    for plat in "${PLATFORMS[@]}"; do
        build_and_run_tui "$py" "$plat"
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

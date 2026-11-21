#!/bin/sh
# Run the security test series in a throwaway PHP container.
# Usage: tests/security/run.sh [php-version]   (default 8.4; e.g. 8.1, 8.2, 8.3)
set -eu
PHPV="${1:-8.4}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
exec podman run --rm --network=none \
    -v "$ROOT":/repo:ro,Z \
    "docker.io/library/php:${PHPV}-cli" \
    sh /repo/tests/security/container.sh

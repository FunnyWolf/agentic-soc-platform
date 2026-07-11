#!/bin/sh
set -eu

requirements="${CUSTOM_REQUIREMENTS_FILE:-/app/custom/requirements.txt}"
target="${CUSTOM_PYTHON_TARGET:-/opt/asp/custom-packages}"

mkdir -p "$target"

if [ ! -f "$requirements" ] || ! grep -qEv '^[[:space:]]*(#|$)' "$requirements"; then
    echo "No custom requirements found at $requirements"
    exit 0
fi

uv pip install --target "$target" -r "$requirements" "$@"

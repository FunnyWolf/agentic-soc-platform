#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: deploy/package-asp-compose.sh --version <version> [--output-dir <dir>] [--backend-image <image>] [--frontend-image <image>]
EOF
}

version=""
output_dir="dist"
backend_image=""
frontend_image=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --backend-image)
      backend_image="${2:-}"
      shift 2
      ;;
    --frontend-image)
      frontend_image="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$version" ]; then
  echo "--version is required" >&2
  usage >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
source_dir="$script_dir/asp-compose"
dist_dir="$root/$output_dir"
staging="$dist_dir/asp-compose"
archive_path="$dist_dir/asp-compose-$version.tar.gz"

rm -rf "$staging"
mkdir -p "$dist_dir"
cp -a "$source_dir" "$staging"
rm -f "$staging/.env"
chmod +x "$staging"/scripts/*.sh

env_example="$staging/.env.example"
if [ -n "$backend_image" ]; then
  sed -i -E "s|^ASP_BACKEND_IMAGE=.*|ASP_BACKEND_IMAGE=$backend_image|" "$env_example"
else
  sed -i -E "s|^(ASP_BACKEND_IMAGE=.*:).*$|\1$version|" "$env_example"
fi

if [ -n "$frontend_image" ]; then
  sed -i -E "s|^ASP_FRONTEND_IMAGE=.*|ASP_FRONTEND_IMAGE=$frontend_image|" "$env_example"
else
  sed -i -E "s|^(ASP_FRONTEND_IMAGE=.*:).*$|\1$version|" "$env_example"
fi

rm -f "$archive_path"
tar -czf "$archive_path" -C "$dist_dir" asp-compose

echo "Created $archive_path"

#!/bin/sh
set -eu

cert_dir="${ASP_TLS_CERT_DIR:-/etc/nginx/certs}"
cert_file="${ASP_TLS_CERT_FILE:-$cert_dir/asp.crt}"
key_file="${ASP_TLS_KEY_FILE:-$cert_dir/asp.key}"

if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
    exit 0
fi

if [ -f "$cert_file" ] || [ -f "$key_file" ]; then
    echo "TLS certificate and key must be provided together: $cert_file $key_file" >&2
    exit 1
fi

mkdir -p "$cert_dir"

hostname="${ASP_PUBLIC_HOSTNAME:-localhost}"
san="DNS:$hostname,DNS:localhost,IP:127.0.0.1"
if [ -n "${ASP_CERT_EXTRA_SAN:-}" ]; then
    san="$san,$ASP_CERT_EXTRA_SAN"
fi

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -sha256 \
    -days "${ASP_SELF_SIGNED_CERT_DAYS:-825}" \
    -keyout "$key_file" \
    -out "$cert_file" \
    -subj "/CN=$hostname" \
    -addext "subjectAltName=$san"

chmod 600 "$key_file"

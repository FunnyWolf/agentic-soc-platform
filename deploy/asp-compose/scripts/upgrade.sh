#!/bin/sh
set -eu

docker compose pull
docker compose run --rm asp-migrate
docker compose up -d
./scripts/doctor.sh

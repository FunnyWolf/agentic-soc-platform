#!/bin/sh
set -eu

if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi

docker compose ps
docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-asp}"
docker compose exec -T redis-stack redis-cli -a "${REDIS_PASSWORD}" ping
docker compose exec -T asp-web python manage.py check
docker compose exec -T asp-web python manage.py shell -c "from apps.agentic.services.custom_scripts import refresh_custom_definitions; result = refresh_custom_definitions(); print(result['counts']); raise SystemExit(0 if result['success'] else 1)"
docker compose exec -T asp-web python - <<'PY'
import boto3
from django.conf import settings

client = boto3.client(
    "s3",
    endpoint_url=settings.AWS_S3_ENDPOINT_URL,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME,
    config=settings.AWS_S3_CLIENT_CONFIG,
)
client.head_bucket(Bucket=settings.AWS_STORAGE_BUCKET_NAME)
PY

echo "ASP deployment checks passed."

#!/bin/sh
set -eu

python manage.py migrate
python manage.py collectstatic --noinput

python - <<'PY'
import time

import boto3
from botocore.exceptions import ClientError
from django.conf import settings

bucket = settings.AWS_STORAGE_BUCKET_NAME

for attempt in range(1, 31):
    client = boto3.client(
        "s3",
        endpoint_url=settings.AWS_S3_ENDPOINT_URL,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
        config=settings.AWS_S3_CLIENT_CONFIG,
    )
    try:
        client.head_bucket(Bucket=bucket)
        break
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if status in {403, 404}:
            client.create_bucket(Bucket=bucket)
            break
        if attempt == 30:
            raise
    except Exception:
        if attempt == 30:
            raise
        time.sleep(2)
else:
    raise RuntimeError(f"Cannot initialize S3 bucket: {bucket}")
PY

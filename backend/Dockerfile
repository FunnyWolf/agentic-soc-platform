FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    DJANGO_SETTINGS_MODULE=asp.settings \
    PYTHONPATH=/opt/asp/custom-packages:/app/custom

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .
RUN mkdir -p /app/custom/modules /app/custom/playbooks /app/custom/data/siem /opt/asp/custom-packages

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000 8001

CMD ["gunicorn", "asp.wsgi:application", "--bind", "0.0.0.0:8000"]

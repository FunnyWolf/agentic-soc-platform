#!/bin/sh
set -eu

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import secrets; print(secrets.token_hex(32))'
        return
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

set_env_value() {
    key="$1"
    value="$2"
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        printf '%s=%s\n' "$key" "$value" >> .env
    fi
}

if [ ! -f .env ]; then
    cp .env.example .env
    postgres_password="$(generate_secret)"
    redis_password="$(generate_secret)"
    rustfs_secret="$(generate_secret)"

    set_env_value DJANGO_SECRET_KEY "$(generate_secret)"
    set_env_value POSTGRES_PASSWORD "$postgres_password"
    set_env_value REDIS_PASSWORD "$redis_password"
    set_env_value RUSTFS_SECRET_KEY "$rustfs_secret"
    echo "Generated .env with random service secrets. Review .env before exposing the deployment."
fi

if grep -Eq '^(DJANGO_SECRET_KEY|POSTGRES_PASSWORD|REDIS_PASSWORD|RUSTFS_SECRET_KEY)=change-me' .env; then
    echo "Refusing to initialize with placeholder secrets in .env. Delete .env to regenerate or update the values manually."
    exit 1
fi

docker compose pull

if [ -f custom/requirements.txt ] && grep -qEv '^[[:space:]]*(#|$)' custom/requirements.txt; then
    docker compose run --rm asp-custom-deps "$@"
fi

docker compose run --rm asp-migrate
docker compose up -d

echo "ASP is starting. Run ./scripts/doctor.sh to verify the deployment."
echo "Create an administrator when needed:"
echo "  docker compose exec asp-web python manage.py createsuperuser"

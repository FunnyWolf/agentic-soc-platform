FROM node:26-alpine AS build

WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

FROM nginx:1.29-alpine

RUN apk add --no-cache openssl

COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY docker-entrypoint.d/10-ensure-cert.sh /docker-entrypoint.d/10-ensure-cert.sh
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 443

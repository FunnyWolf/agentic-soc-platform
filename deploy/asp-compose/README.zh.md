# ASP Docker Compose 部署

英文版本：[README.md](README.md)

这个发布包用于在单台主机上通过 Docker Compose 部署 ASP。

## 首次部署

1. 执行 `./scripts/init.sh`。如果 `.env` 不存在，脚本会从 `.env.example` 创建 `.env`，并生成随机服务密钥。
2. 如有需要，将自定义 Module、Playbook、SIEM YAML 或 Python 依赖放到 `custom/` 目录。
3. 初始化并启动 ASP。如果 `custom/requirements.txt` 不为空，`init.sh` 后面的参数会传给 `uv pip install`：

   ```bash
   ./scripts/init.sh --index-url https://pypi.org/simple
   ```

   需要代理时使用标准环境变量：

   ```bash
   HTTP_PROXY=http://proxy.example:8080 HTTPS_PROXY=http://proxy.example:8080 \
   ./scripts/init.sh --index-url https://pypi.org/simple
   ```

4. 如果没有额外 Python 依赖，直接执行：

   ```bash
   ./scripts/init.sh
   ```

5. 创建管理员：

   ```bash
   docker compose exec asp-web python manage.py createsuperuser
   ```

初始化后请检查 `.env`。你可以继续修改密码、主机名或端口。不要在 `.env` 中保留 `change-me-*` 占位密钥；`init.sh` 会拒绝使用占位密钥启动。

## HTTPS 证书

`asp-frontend` 只监听 HTTPS。宿主机绑定地址和端口由 `.env` 中的 `ASP_BIND` 和 `ASP_HTTPS_PORT` 控制，默认值适合服务器部署：

```text
ASP_BIND=0.0.0.0
ASP_HTTPS_PORT=443
```

如果 `certs/asp.crt` 和 `certs/asp.key` 不存在，前端容器首次启动时会生成自签名证书。生成的证书会使用 `ASP_PUBLIC_HOSTNAME`，并包含 `localhost` 和 `127.0.0.1` 作为 SAN。可以通过 `ASP_CERT_EXTRA_SAN` 添加额外域名或 IP：

```text
ASP_CERT_EXTRA_SAN=DNS:asp.example.com,IP:10.0.0.10
```

如需使用自定义证书，请在启动前放置这两个文件，或替换后重启前端：

```text
certs/asp.crt
certs/asp.key
```

```bash
docker compose restart asp-frontend
```

## 管理界面

Redis Stack 和 RustFS 自带管理界面。发布包直接暴露它们的官方 HTTP 管理端口，避免反向代理带来的静态资源或 WebSocket 兼容问题：

- Redis Stack UI：`http://<server>:8001`
- RustFS Console：`http://<server>:9001`

RustFS S3 API 默认保持容器内部访问，不映射到宿主机。

宿主机绑定地址和端口由 `.env` 控制：

```text
ASP_MANAGEMENT_BIND=0.0.0.0
ASP_REDIS_UI_PORT=8001
ASP_RUSTFS_CONSOLE_PORT=9001
```

默认绑定地址是 `0.0.0.0`，适合服务器部署。如果管理界面不应被不可信网络访问，请使用防火墙或 VPN 进行访问控制。

## 定制定义

- `custom/modules/*.py` 存放自定义 Module 脚本。
- `custom/playbooks/*.py` 存放自定义 Playbook 脚本。
- `custom/data/modules/<module_slug>/raw_alert_*.json` 存放 Module 开发样本。
- `custom/data/siem/*.yaml` 存放自定义 SIEM schema 文件。
- `custom/data/playbooks/<playbook_slug>/*.md` 存放自定义 Playbook prompt。
- `custom/requirements.txt` 存放额外 Python 依赖。

只修改脚本或 YAML 定义后，可以在 ASP 中使用 **System Settings > Runtime > Refresh / Validate**。修改 Python 包依赖或公共 helper module 后，需要重新执行 `asp-custom-deps` 并重启相关容器。

## 日志

后端进程日志会挂载到 `./logs`：

```text
logs/django.log
logs/asgi.log
logs/agentic-module-worker.log
logs/agentic-case-analysis-worker.log
logs/agentic-playbook-worker.log
logs/elk-action-worker.log
```

容器标准输出和标准错误仍可通过 `docker compose logs` 查看。

## 运维

查看服务状态并执行部署诊断：

```bash
docker compose ps
./scripts/doctor.sh
```

重启所有服务：

```bash
docker compose restart
```

只重启 Web/API 入口：

```bash
docker compose restart asp-frontend asp-web asp-asgi
```

只重启后台 Worker：

```bash
docker compose restart asp-worker-module asp-worker-case-analysis asp-worker-playbook asp-worker-elk-action
```

修改 `.env`、`compose.yaml` 或端口映射后，执行：

```bash
docker compose up -d
```

停止容器但保留 Docker 数据卷：

```bash
docker compose stop
```

不要在生产环境执行 `docker compose down -v`，除非明确要删除 PostgreSQL、Redis 和 RustFS 的 Docker 数据卷。

## 备份 & 恢复

备份和恢复都在目录名为 `asp-compose` 的部署目录中执行，避免 Docker Compose volume 名称变化。

停机全量备份：

```bash
BACKUP_DIR="$PWD/backups/asp-full-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
docker compose stop
tar -czf "$BACKUP_DIR/files.tar.gz" --exclude='./backups' .env .env.example compose.yaml scripts custom certs logs
docker run --rm \
  -v asp-compose_postgres-data:/volumes/postgres-data:ro \
  -v asp-compose_redis-data:/volumes/redis-data:ro \
  -v asp-compose_rustfs-data:/volumes/rustfs-data:ro \
  -v asp-compose_custom-python-packages:/volumes/custom-python-packages:ro \
  -v asp-compose_static-files:/volumes/static-files:ro \
  -v "$BACKUP_DIR:/backup" \
  alpine sh -lc 'cd /volumes && tar -czf /backup/volumes.tar.gz postgres-data redis-data rustfs-data custom-python-packages static-files'
docker compose up -d
./scripts/doctor.sh
```

全量恢复：

```bash
BACKUP_DIR=/path/to/asp-full-backup
tar -xzf "$BACKUP_DIR/files.tar.gz" -C .
docker compose down --remove-orphans
docker run --rm \
  -v asp-compose_postgres-data:/volumes/postgres-data \
  -v asp-compose_redis-data:/volumes/redis-data \
  -v asp-compose_rustfs-data:/volumes/rustfs-data \
  -v asp-compose_custom-python-packages:/volumes/custom-python-packages \
  -v asp-compose_static-files:/volumes/static-files \
  -v "$BACKUP_DIR:/backup" \
  alpine sh -lc '
    for dir in postgres-data redis-data rustfs-data custom-python-packages static-files; do
      rm -rf "/volumes/$dir"/* "/volumes/$dir"/.[!.]* "/volumes/$dir"/..?*
    done
    tar -xzf /backup/volumes.tar.gz -C /volumes
  '
docker compose up -d
./scripts/doctor.sh
```

恢复前不要修改 `asp-compose` 目录名。

## 升级

升级前先完成一次停机全量备份。

编辑 `.env`，把镜像标签更新到目标版本：

```text
ASP_BACKEND_IMAGE=ghcr.io/funnywolf/agentic-soc-platform/asp-backend:<version>
ASP_FRONTEND_IMAGE=ghcr.io/funnywolf/agentic-soc-platform/asp-frontend:<version>
```

执行升级：

```bash
./scripts/upgrade.sh
```

`upgrade.sh` 会拉取镜像、执行数据库迁移、启动服务，并执行 `./scripts/doctor.sh`。

只有发布说明明确要求更新发布包文件时，才替换 `compose.yaml`、`scripts/` 和 `.env.example`。请保留现有 `.env`、`custom/`、`certs/` 和 Docker named volumes。

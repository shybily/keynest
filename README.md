# 枢钥 · Keynest

Keynest（枢钥）是一个面向自建服务的配置管理中心，使用 Go、Iris 和 SQLite。后台页面通过 `go:embed` 随二进制一起发布；配置按项目、环境、服务组织，字段 Schema 与服务环境的结构化配置值分开管理。

## 开发运行

当前版本：`v0.3.2`。

需要 Go 1.27 或更新版本。首次启动前设置三个引导变量：

```powershell
$env:KEYNEST_ADMIN_PASSWORD = "替换为管理员密码"
$env:KEYNEST_AUTH_SECRET = "替换为至少 32 字节的随机值"
$env:KEYNEST_ENCRYPTION_KEY = "替换为至少 32 字节的独立随机值"
go run .\cmd\keynest
```

配置中心默认监听 `:8080`，SQLite 文件默认位于 `data/keynest.db`。可通过 `KEYNEST_ADDR` 和 `KEYNEST_DB` 修改。生产环境请通过 TLS 反向代理访问，并持久化、备份 SQLite 文件。

`KEYNEST_ENCRYPTION_KEY` 用于加密数据库中的配置值。该密钥必须妥善备份；丢失后，已保存配置无法解密。不要与数据库文件放在同一备份介质或提交到版本库。管理员密码、会话签名密钥和加密密钥都应使用独立的随机值。

构建单二进制：

```powershell
go build -ldflags="-X main.version=0.3.0 -X github.com/shybily/keynest/web.Version=0.3.0" -o .\bin\keynest.exe .\cmd\keynest
```

构建机需要 Go 和依赖下载能力；运行机器只需部署二进制、设置引导变量并提供持久化数据目录。

详细安装、配置导入、服务凭证、传输加密及 Go SDK 使用流程见[使用说明](./docs/使用说明.md)。

### Docker 部署

在项目根目录创建 `compose.yaml`：

```yaml
services:
  keynest:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    env_file:
      - .env
    environment:
      KEYNEST_ADDR: ":8080"
      KEYNEST_DB: /var/lib/keynest/keynest.db
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - keynest-data:/var/lib/keynest

volumes:
  keynest-data:
```

在同一目录创建仅部署账号可读的 `.env`，填入独立生成的随机密钥；不要提交该文件：

```dotenv
KEYNEST_ADMIN_PASSWORD=replace-with-a-strong-password
KEYNEST_AUTH_SECRET=replace-with-at-least-32-random-bytes
KEYNEST_ENCRYPTION_KEY=replace-with-a-different-32-byte-random-key
# Optional Cloudflare cache purge configuration:
# KEYNEST_CLOUDFLARE_ENABLED=true
# KEYNEST_CLOUDFLARE_API_TOKEN=replace-with-a-zone-scoped-token
# KEYNEST_CLOUDFLARE_ZONE_ID=your-cloudflare-zone-id
# KEYNEST_PUBLIC_URL=https://config.example.com
```

构建并启动：

```powershell
docker compose build keynest
docker compose up -d keynest
docker compose ps keynest
docker compose logs --tail=100 keynest
```

管理页面仅映射到宿主机 `127.0.0.1:8080`，本机访问 `http://127.0.0.1:8080/`；若该端口已占用，可修改端口映射左侧的宿主机端口。远程管理请使用 SSH 本地端口转发。其他加入同一个 Compose 网络的服务可通过 `http://keynest:8080` 访问 Keynest。不要直接将管理端口公开到公网；对外提供服务时应配置 TLS 反向代理。备份 Compose 卷中的 SQLite 数据库，并单独安全备份 `.env` 中的 `KEYNEST_ENCRYPTION_KEY`。Keynest 不会自动重启其他服务。

## 管理配置

管理页面按“项目 → 环境 → 服务”组织资源：

- 项目包含多个环境；删除项目会级联删除其环境、服务和密钥。
- 环境包含多个服务；删除环境会级联删除该环境下的配置和密钥。
- 新建服务时原子生成该服务的访问令牌及 RSA 密钥。
- 服务密钥可重新生成或删除；重新生成后旧令牌和私钥立即失效。
- 配置直接绑定到项目、环境和服务，并按草稿、发布版本、历史版本管理。

登录后选择项目、环境和服务，再编辑该服务环境的 Schema 字段。字段路径支持点分层级，例如 `database.maxOpenConns`。类型包括字符串、整数、数字、布尔、枚举、密钥和 JSON；字段可映射到 `.env` 变量名和 YAML 路径。也可导入 `.env`、YAML 或 JSON 文件，导入结果先保存为草稿，不会自动发布。

草稿保存不会影响服务读取结果。发布前会校验字段路径、类型、必填值及重复映射；发布成功后产生递增版本。发布历史可恢复为草稿，再次发布后成为新版本。

### Cloudflare CDN 刷新

Cloudflare 缓存刷新默认关闭。需要时在部署环境中设置以下变量并重启 Keynest：

- `KEYNEST_CLOUDFLARE_ENABLED=true`：启用发布后的 CDN 刷新；未设置或为 `false` 时关闭。
- `KEYNEST_CLOUDFLARE_API_TOKEN`：Cloudflare API Token。
- `KEYNEST_CLOUDFLARE_ZONE_ID`：目标 Zone ID。
- `KEYNEST_PUBLIC_URL`：Keynest 的规范 HTTPS 公开地址，不带查询参数或片段。

Token 至少需要目标 Zone 的 `Zone:Read` 和 `Cache Purge` 权限，用于校验 Zone 访问权及清理缓存。Token 只从环境变量读取，不保存到数据库或后台页面。

开关开启后，Keynest 会校验配置、Token 状态及 Zone 访问权。必要配置缺失或校验无效时，Keynest 仍正常启动和发布配置，但自动暂停 CDN 刷新；暂时无法连接 Cloudflare 时会显示为不可用并定期重试校验。Token 还必须具有 `Cache Purge` 权限；若 Cloudflare 在首次实际刷新时拒绝该权限，刷新会自动暂停，修正 Token 权限后重启 Keynest。管理后台侧栏展示 CDN 状态、待刷新任务数及最近错误。

发布配置与针对该服务的三条 CDN 刷新 URL（加密配置、`.env` 渲染、YAML 渲染）会在同一 SQLite 事务中记录。刷新在后台执行，失败会保留任务并退避重试，不会回滚发布版本。此功能只清理缓存，不会自动启用 Cloudflare 缓存规则；多 Keynest 公开域名部署时，当前只刷新 `KEYNEST_PUBLIC_URL` 指定的规范地址。

### 服务读取凭证与传输加密

访问密钥随服务创建：新建服务时自动生成令牌和 RSA 密钥。凭证明文只在创建或重新生成时显示一次；数据库只保存 SHA-256 摘要和加密私钥。私钥可在后台通过管理员认证下载。读取 API 的凭证范围为项目、环境和服务。

配置内容由随机 AES-256-GCM 密钥加密，再用服务公钥通过 RSA-OAEP-SHA256 加密该 AES 密钥。读取 API 只返回加密信封；SDK 使用服务私钥解密。凭证授权与内容加密是两层独立保护。下载私钥会被审计，发生泄露时撤销凭证并重新创建密钥。此加密不替代 TLS：生产环境仍必须使用 HTTPS 来认证服务端并保护访问凭证。

配置 JSON：

```text
GET /api/v1/configs/{project}/{environment}/{service}
Authorization: Bearer <token>
```

该接口响应为加密信封 JSON，不会直接返回配置明文；密钥 ID 和版本号用于 SDK 解密及客户端版本判断。

渲染已发布配置：

```text
GET /api/v1/configs/{project}/{environment}/{service}/render/env
GET /api/v1/configs/{project}/{environment}/{service}/render/yaml
Authorization: Bearer <token>
```

管理端接口以 `/api/v1/admin` 为前缀，使用登录 Cookie。登录后会话空闲 30 分钟、最长 12 小时，写操作必须同时通过 CSRF Cookie/请求头双提交和 Origin/Referer 校验。同一 IP 在 15 分钟内连续 5 次登录失败会被锁定 15 分钟，并返回 `429` 与 `Retry-After`。反向代理部署时设置 `KEYNEST_TRUSTED_PROXIES` 为代理 IP 或 CIDR，否则按直连地址限流。配置列表、草稿、发布、历史、渲染预览和访问凭证管理均由管理端鉴权保护。`GET /healthz` 提供健康检查。

## Go SDK

```go
import (
    "context"
    "log"
    "os"

    "github.com/shybily/keynest/sdk"
)

func readConfig() {
ctx := context.Background()
privateKeyPEM, err := os.ReadFile("keynest-private.pem")
if err != nil {
    log.Fatal(err)
}
client, err := sdk.New(
    "https://config.example.internal",
    os.Getenv("KEYNEST_ACCESS_TOKEN"),
    privateKeyPEM,
    nil,
)
if err != nil {
    log.Fatal(err)
}

var settings struct {
    HTTP struct {
        Port int `json:"port"`
    } `json:"http"`
}
version, err := client.Get(ctx, sdk.Address{
    Project: "my-project",
    Environment: "prod",
    Service: "my-service",
}, &settings)
_ = version
_ = settings
}
```

SDK 构造时需提供本地私钥 PEM；`Fetch` 解密后返回结构化文档；`Get` 将配置值解码到业务结构体；`Watch` 周期拉取版本变化并调用业务回调。可选的本地加密缓存支持配置中心短暂不可用时继续使用上次成功获取的配置，详见[使用说明](./docs/使用说明.md)。

使用 `sdk` 包时，业务项目可将 `github.com/shybily/keynest` 作为 Go module 依赖引入。服务自身的连接密钥、配置中心地址、读取凭证和下载的私钥属于启动引导配置，不应依赖配置中心提供。

SDK 日志可接入 `slog` 或其他日志库。第三方 logger 可通过 `LoggerFunc` 适配，例如 zerolog：

```go
logger := zerolog.New(os.Stdout)

client, err := sdk.NewWithOptions(baseURL, token, privateKeyPEM, nil, sdk.Options{
    Logger: sdk.LoggerFunc(func(level sdk.LogLevel, event, message string, fields sdk.LogFields) {
        var entry *zerolog.Event
        switch level {
        case sdk.LogLevelDebug:
            entry = logger.Debug()
        case sdk.LogLevelWarn:
            entry = logger.Warn()
        case sdk.LogLevelError:
            entry = logger.Error()
        default:
            entry = logger.Info()
        }
        entry.Str("event", event).Interface("fields", fields).Msg(message)
    }),
})
```

## 当前限制

- 首版采用 SQLite 单实例，不适用于多写入节点共享同一数据库文件的部署方式。
- 发布配置不会直接修改正在运行进程的环境变量，也不会重启容器。
- `.env` / YAML 只渲染 Schema 中声明且映射的字段。
- 配置值加密使用单一部署密钥；密钥轮换需要后续提供迁移工具。
- 配置中心不管理证书、Caddy/nginx 等配置，也不执行远程部署命令。

## 验证

```powershell
go test ./...
go build .\cmd\keynest
```

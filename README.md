<p align="center">
  <img src="./assets/brand/hero-ice.png" width="256" alt="Aegis logo" />
</p>

<h1 align="center">Aegis</h1>

Aegis 是 Helios 的认证与授权服务——登录、令牌、会话、权限判定都归它管。它跑的是 OAuth 2.1 授权码流程，接得住多种身份提供方，也处理 MFA 和 WebAuthn 这类挑战。身份数据本身不在它这里存，那部分属于 Hermes；Aegis 只按固定的 Schema 标签生成自己的客户端绑定。

Aegis is Helios' authentication and authorization service: OAuth 2.1 flows, identity-provider orchestration, MFA and WebAuthn challenges, token issuance, sessions, and relationship-based access checks. It doesn't own identity persistence — that's Hermes; Aegis consumes it through generated client bindings pinned to a Schema tag.

## 本地运行

需要 Redis，以及一个正在运行的 Hermes 实例。

```bash
cp example.toml config.toml
make run
```

HTTP 服务默认监听 `18000` 端口。

## Hermes 客户端绑定

生成的 Go 客户端绑定放在 `internal/rpc/hermes/v1`，是 Aegis 私有的。语言无关的 Schema 由 [Hermes](https://github.com/heliantheon/hermes) 发布，用独立的 `schema/*` 标签管理版本。

```bash
make generate
make check-generate
```

日常构建直接使用仓库里已提交的生成文件，不需要装 Buf，也不需要联网。

## 开发

```bash
make test
make lint
make build
```

设计说明写在 [`docs/`](docs/) 里。可复用的客户端与 guard 代码在 [`aegis-go`](https://github.com/heliantheon/aegis-go)，别在这里重复实现。
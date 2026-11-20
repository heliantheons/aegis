# Aegis Token 设计文档

## 1. 概述

Aegis 使用 **PASETO v4 Public Token**（Ed25519 签名）作为业务访问凭证格式，定义了以下 5 种 PASETO Token。OIDC ID Token 单独使用 RS256 JWT，见第 8 节；它面向登录客户端，独立于业务访问凭证。

| 类型 | 标识 | 用途 | 签发方 | 验证方 | Footer | 加密数据 |
|------|------|------|--------|--------|--------|----------|
| CAT | `cat` | 客户端自签发凭证 | 应用 | Aegis | kid | 无 |
| UAT | `uat` | 用户访问令牌 | Aegis | 应用 | kid | sub（v4.local） |
| SAT | `sat` | 服务访问令牌（M2M） | Aegis | 应用 | kid | 无 |
| XAT | `challenge` | 验证挑战令牌 | Aegis | Aegis | kid | 无 |
| SSO | `sso` | 单点登录会话（内部） | Aegis | Aegis | kid | sub（v4.local） |

---

## 2. PASETO Token 格式

### 2.1 结构

```
v4.public.<payload>.<footer>
```

| 部分 | 说明 |
|------|------|
| `v4` | PASETO 版本 |
| `public` | 公钥签名模式（Ed25519） |
| `payload` | Base64URL(claims_json + signature) |
| `footer` | JSON，包含 kid（密钥标识） |

### 2.2 Footer 格式（所有 Token 统一）

```json
{"kid":"k4.pid.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
```

- `kid`：PASERK 格式的签名密钥标识符
- 使用 BLAKE2b-264 从公钥派生，确定性、不可逆
- 用于密钥轮换场景下精确匹配验签公钥

### 2.3 通用 Claims

所有 Token 共享的标准字段：

```json
{
  "iss": "string",
  "aud": "string",
  "sub": "string",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T01:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "string"
}
```

| Claim | 类型 | 说明 |
|-------|------|------|
| `iss` | string | 签发者 |
| `aud` | string | 目标受众 |
| `sub` | string | 主体（可选，UAT/SSO 为加密的 v4.local token） |
| `iat` | RFC3339 | 签发时间 |
| `exp` | RFC3339 | 过期时间 |
| `nbf` | RFC3339 | 生效时间 |
| `jti` | string | Token ID（16 字节随机 hex） |

### 2.4 扩展 Claims

| Claim | 使用者 | 说明 |
|-------|--------|------|
| `token_type` | SAT | 显式令牌种类，固定为 `sat`，包含在签名内 |
| `cli` | UAT, SAT, XAT, SSO | 应用/签发者 ID |
| `scope` | UAT, SAT | 授权范围（空格分隔） |
| `ctp` | XAT | 验证方式（ChannelType） |
| `typ` | XAT | 业务场景 |

---

## 3. 嵌套加密结构

### 3.1 双层 Token 架构（UAT/SSO）

UAT 和 SSO Token 使用嵌套 PASETO Token 结构存储敏感数据：

```
外层 v4.public Token（签名）:
  payload: { iss, aud, cli, scope, exp, ..., sub: "<v4.local token>" }
  footer:  { "kid": "k4.pid.xxxx" }   ← 签名密钥的 PASERK pid

内层 v4.local Token（加密，嵌在 sub 字段中）:
  payload: { 加密的用户信息 / 域身份映射 }
  footer:  { "kid": "k4.lid.yyyy" }   ← 加密密钥的 PASERK lid
```

- 外层 footer 的 `k4.pid` 标识签名密钥，用于验签
- 内层 footer 的 `k4.lid` 标识加密密钥，用于解密 sub
- 两个 kid 来自不同的 Seed，轮换完全独立

### 3.2 kid 派生（PASERK 规范）

**签名密钥 kid（k4.pid）**：

```
paserk = "k4.public." + base64url(ed25519_public_key_bytes)
h      = "k4.pid."
d      = BLAKE2b(message: h || paserk, output_size: 33)
kid    = h + base64url(d)    // 总长 51 字符
```

**加密密钥 kid（k4.lid）**：

```
paserk = "k4.local." + base64url(symmetric_key_bytes)
h      = "k4.lid."
d      = BLAKE2b(message: h || paserk, output_size: 33)
kid    = h + base64url(d)    // 总长 51 字符
```

---

## 4. Token 类型详解

### 4.1 CAT (Client Access Token)

**用途**：应用自签发凭证，用于 Client-Credentials 流程向 Aegis 请求 SAT。

**Claims**

```json
{
  "iss": "app_123456",
  "sub": "app_123456",
  "aud": "https://aegis.heliannuuthus.com/api",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T00:05:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890"
}
```

**Footer**：`{"kid":"k4.pid.xxxx"}` — 应用密钥的 pid

**特性**

- 短期有效（推荐 1-5 分钟）
- 一次性交换使用
- 不含 `cli`、`scope`
- `sub` = 应用 ID（明文）

---

### 4.2 UAT (User Access Token)

**用途**：用户访问令牌，代表用户身份调用受保护资源。

**外层 Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "service_789",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T01:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "scope": "openid profile email",
  "sub": "v4.local.加密的用户信息..."
}
```

**外层 Footer**：`{"kid":"k4.pid.xxxx"}` — domain.main 的 pid

**内层 v4.local Token（sub 字段值）的解密内容**

```json
{
  "sub": "openid_xxx",
  "nickname": "张三",
  "picture": "https://example.com/avatar.jpg",
  "email": "user@example.com",
  "phone": "13800138000"
}
```

**内层 Footer**：`{"kid":"k4.lid.yyyy"}` — service.key 的 lid

**Scope 定义**

| Scope | 允许访问 |
|-------|----------|
| `openid` | sub |
| `profile` | nickname, picture |
| `email` | email |
| `phone` | phone |
| `offline_access` | 请求 Refresh Token |

**特性**

- 推荐有效期 15-60 分钟
- 配合 Refresh Token 使用
- 敏感信息加密存储于 sub 字段（嵌套 v4.local token）

---

### 4.3 SAT (Service Access Token)

**用途**：服务间 M2M 通信凭证，无用户上下文。

**Claims**

```json
{
  "token_type": "sat",
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "service_789",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-02T00:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890"
}
```

**Footer**：`{"kid":"k4.pid.xxxx"}` — domain.main 的 pid

**特性**

- 推荐有效期 1-24 小时
- 无用户信息；可选 `sub` 仅表示服务主体，不进入 UAT 的身份解密流程
- 适用于后台任务、微服务调用

---

### 4.4 XAT (Challenge Token)

**用途**：证明用户已完成特定身份验证挑战，用于 MFA 和敏感操作。

**Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "https://aegis.heliannuuthus.com/api",
  "sub": "user@example.com",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T00:15:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "ctp": "email-code",
  "typ": "login"
}
```

**Footer**：`{"kid":"k4.pid.xxxx"}` — domain.main 的 pid

**特性**

- 推荐有效期 5-15 分钟
- 一次性使用
- `sub` = 完成验证的 principal（明文）

---

### 4.5 SSO Token（内部专用）

**用途**：跨应用单点登录会话，存储于浏览器 Cookie，仅 Aegis 内部使用。

**外层 Claims**

```json
{
  "iss": "aegis",
  "cli": "aegis",
  "aud": "aegis",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-08T00:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "sub": "v4.local.加密的域身份映射..."
}
```

**外层 Footer**：`{"kid":"k4.pid.xxxx"}` — sso.master_key 的 pid

**内层 v4.local Token（sub 字段值）的解密内容**

```json
{
  "domain_consumer": "openid_xxx",
  "domain_platform": "openid_yyy"
}
```

**内层 Footer**：`{"kid":"k4.lid.yyyy"}` — sso.master_key 的 lid

**特性**

- 默认有效期 7 天
- 域隔离身份（每个域独立 OpenID）
- 自签发自验证（iss = cli = aud = "aegis"）
- 无 `scope`

---

## 5. 统一签发 / 验证架构

### 5.1 设计原则

以下 PASETO Token 类型共享 `Issue` 和 `Verify` 入口，通过接口多态区分行为差异；JWT ID Token 使用独立的 `IssueIDToken` 入口。

- **签发差异**由 `encryptableToken` 接口决定：实现该接口的 Token（UAT、SSO）会将 payload 加密到 sub 字段；未实现的（SAT、XAT）直接签名
- **验证差异**由 `decryptableToken` 接口决定：实现该接口的 Token 在验签后自动解密 sub 并填充数据
- **密钥选择**由 Token 自身的 `GetClientID()` 和 `GetAudience()` 驱动，无需特殊分支

### 5.2 Token 构建（Builder 模式）

所有 Token 通过统一的 `ClaimsBuilder + TokenTypeBuilder` 模式构建：

```
token := NewClaimsBuilder().
    Issuer(issuer).
    ClientID(clientID).
    Audience(audience).
    ExpiresIn(duration).
    Build(typeBuilder)    // UAT / SAT / XT / CAT / SSOTokenBuilder
```

`TokenTypeBuilder` 接口负责将通用 Claims 与类型特有字段组合为具体 Token 实例。

### 5.3 签发流程（`Service.Issue`）

```
1. Build: Token → *paseto.Token（通过 tokenBuilder 接口）
2. 检查是否实现 encryptableToken 且 HasUser()：
   是 → MarshalPayload → Encrypt(audience) → SetSubject(encrypted)
   否 → 跳过
3. Sign(clientID) → 返回 token 字符串
```

密钥选择规则：
- 签名：`domainKeyStore.Get(clientID)` — SSO 时 clientID = "aegis"
- 加密：`serviceKeyStore.Get(audience)` — SSO 时 audience = "aegis"

### 5.4 验证流程（`Service.Verify`）

```
1. UnsafeParse → 提取 claims（不验签）
2. DetectType → 判断 Token 类型
3. 选择验签 KeyStore：
   CAT → appKeyStore（应用自签，用应用公钥验证）
   其他 → domainKeyStore（Aegis 签发，用域公钥验证）
4. 验签（遍历候选 Seed，通过 kid 精确匹配）
5. ParseToken → 解析为具体 Token 类型
6. 检查是否实现 decryptableToken：
   是 → Decrypt(audience) → UnmarshalPayload → 填充数据
   否 → 跳过
7. 返回 Token（调用方按需类型断言）
```

验签密钥匹配细节：
```
a. 用 clientID 从 KeyStore 获取所有 Seed
b. 逐个派生公钥，计算 k4.pid
c. 与 footer kid 做 constant-time comparison
d. 匹配成功 → ParseV4Public 验签
```

---

## 6. 安全设计

### 6.1 签名与加密

| Token | 签名密钥来源 | Footer kid 类型 | 加密密钥来源 | 内层 kid 类型 |
|-------|-------------|-----------------|-------------|--------------|
| CAT | `app.key` | k4.pid | — | — |
| UAT | `domain.main` | k4.pid | `service.key` | k4.lid |
| SAT | `domain.main` | k4.pid | — | — |
| XAT | `domain.main` | k4.pid | — | — |
| SSO | `sso.master_key` | k4.pid | `sso.master_key` | k4.lid |

### 6.2 安全要点

- kid 是公钥/对称密钥的 BLAKE2b 哈希摘要，明文存放无安全风险
- 外层签名覆盖整个 payload（包括加密的 sub），防止加密数据被替换
- 内层 v4.local 使用 XChaCha20-Poly1305 (AEAD)，提供认证加密
- kid 比对使用 constant-time comparison，防止时序侧信道攻击
- UnsafeParse 仅用于确定 KeyStore 查找目标，kid 用于精确匹配

### 6.3 有效期建议

| Token | 推荐有效期 | 说明 |
|-------|------------|------|
| CAT | 1-5 分钟 | 一次性交换 |
| UAT | 15-60 分钟 | 配合 Refresh Token |
| SAT | 1-24 小时 | M2M 场景 |
| XAT | 5-15 分钟 | 验证窗口 |
| SSO | 7-30 天 | 会话保持 |

---

## 7. Token 类型检测

### 7.1 判断逻辑

```
1. 有非空 "token_type" → 使用显式类型（SAT 为 "sat"）；未知类型拒绝
2. iss == aud == cli（三者相等且非空） → SSO
3. 有非空 "typ" → XAT
4. 有 "cli" → UAT（sub 加密）
5. 无 "cli"/"typ" → CAT
```

> 显式令牌种类优先于 SSO 的启发式判断。`token_type` 与 Challenge 的业务 `typ` 相互独立；签发方和消费方使用 Aegis Go SDK `v0.0.2`，并重新签发不带类型标识的旧 SAT。

## HTTP 请求与响应边界

跨域、缓存和导航隐私按行为组合，复用独立中间件；现有 PASETO 凭证格式保持不变。

- 服务仅提供一份 `cors.origins`，用于显式信任可调用登录会话、context、connections、idps、login、binding、challenge、logout 等接口的前端；Aegis endpoint 始终包含在可信来源中，额外列表可为空。环境覆盖名为 `AEGIS_CORS_ORIGINS`，列表使用空格分隔。可信 origin 必须是无路径、查询、用户信息的完整 HTTP(S) origin，不允许 `*` 或 `null`。应用 `allowed_origins` 独立控制 token、revoke 及后续 UserInfo 等客户端协议操作，不授予登录 API 访问权。
- profile、identities、mfa 等账号业务接口不挂载 CORS，也不提供跨域预检；前端通过业务服务自己的同源地址访问，例如 Iris 的相对路径 `/api`。接口保留现有 Iris Bearer guard、用户归属校验与 NoStore；服务端调用仍按业务凭证和权限处理，不新增来源白名单。授权入口保留现有 `POST /api/authorize`，HTTP 中间件重构不迁移业务路由。
- `middleware.Preflight` 和 `middleware.CORS` 是独立中间件：前者只处理同时包含 OPTIONS、Origin 和 Access-Control-Request-Method 的完整预检，后者只校验实际请求的来源并生成响应头。静态来源场景在路由上按 `Preflight(options)`、`CORS(options)` 顺序组合；不使用模式布尔值。token/revoke 只挂载通用 POST 预检，实际请求在验证客户端后调用 `AllowOrigin` 检查应用策略，拒绝来源返回 403。跨域中间件不解析请求体、`client_id` 或应用缓存；允许响应暴露 `Location`、`WWW-Authenticate` 和 `X-Trace-ID`。
- 元数据和公钥是公开信息；`/api/pubkeys` 保留任意来源读取及公共缓存，不开放跨域凭证。`middleware.NoStore` 在处理器执行前设置 `Cache-Control: no-store` 和 `Pragma: no-cache`，覆盖认证会话、账户管理、token、撤销和 Bearer 权限检查的成功、错误及跳转响应。`middleware.NoReferrer` 用于授权入口及上游身份提供方回调。
- `middleware.ProtectCookieRequests` 保护登录组 Cookie 状态变更接口。明确受信任 Origin 即使携带 `Sec-Fetch-Site: cross-site` 也允许；不可信 Origin 即使标为 same-site/same-origin 也拒绝。Origin 缺省时保留同源 Fetch Metadata 或可信 Referer 回退；缺少来源依据返回 403。GET、HEAD 和 OPTIONS 沿用路由行为。token 交换、显式 token 撤销和 Bearer 管理接口不挂载此防护；上游回调继续使用现有交易校验。

## 8. 标准 OIDC 登录与 ID Token

### 8.1 协议边界

- Issuer 为 Aegis 的 HTTPS `endpoint + /api`；ID Token 的 `aud` 为登录应用的 `client_id`。
- 使用 Authorization Code + PKCE S256。请求 `openid` scope 时，授权码兑换同时返回标准 JWT `id_token` 和原有 PASETO `access_token`。
- ID Token 使用独立 RSA 密钥和 RS256 签名，JOSE header 包含 `kid`。`iat`、`exp`、`auth_time` 使用 Unix 秒，`nonce` 原样关联授权请求。
- `profile` 对应 `nickname`、`picture`，`email` 对应 `email`，`phone` 对应 `phone_number`；仅返回已授予 scope 对应的资料。
- UAT/SAT/CT 的格式、claims、域签名、嵌套加密和 Go guard 解析契约保持原样。ID Token 不进入 PASETO 的构建或类型检测链路。

### 8.2 公开端点

| 端点（相对 issuer） | 行为 |
| --- | --- |
| `GET /.well-known/openid-configuration` | 返回 issuer、标准端点、签名算法和支持的协议能力 |
| `GET /jwks` | 返回当前及轮换中的 RSA 公钥 JWK，不返回私钥 |
| `GET /authorize`、`POST /authorize` | 标准浏览器授权入口，分别接收 query 和 form 请求，使用浏览器跳转，不开放 CORS |
| `POST /token` | 接收标准 form 授权码和刷新请求；保留已有多 audience 扩展 |
| `GET /userinfo`、`POST /userinfo` | 验证 UserInfo 资源的 PASETO UAT，校验 issuer、audience、openid scope，返回标准用户声明 |

未指定 audience 的标准登录请求使用 `oidc.default-audience`（默认 Iris）；仍执行现有应用服务关系校验。UserInfo 仅接受该受众的用户访问令牌。显式请求其他业务资源的 Access Token 继续用于相应业务 API。

UserInfo 在验证 UAT 的签名、issuer 和 audience 后，使用 Token 中确认的 client_id 检查应用 `allowed_origins`；URL 查询参数不能选择其他客户端的来源策略。跨域预检不携带 Token，先执行通用预检，实际请求仍需通过完整的凭证、来源和 scope 校验。

路由独立选择参数来源（`QueryParameters` / `BodyParameters`）及响应方式（`BrowserResponse` / `ActionResponse`），共享同一授权核心，不根据 HTTP method 推断。标准 GET 授权入口选择 query/browser，标准 POST 授权入口选择 body/browser，均使用 `/api/authorize` 路径。浏览器错误跳转前仍需验证注册的 client 与 redirect URI。

内部 Pallas 的 XHR 登录/MFA 操作继续使用 HTTP 300 与 `Location` 指令；浏览器顶层授权入口使用正常 HTTP 跳转。重定向 URI 精确匹配注册值，授权错误仅回到已验证的客户端 URI。`prompt`、`max_age` 与实际认证时间共同决定是否允许 SSO 复用。

当前没有持久化历史授权记录，每次 `openid` 登录均要求用户明确同意；有效 SSO 会话配合 `prompt=none` 时返回 `consent_required`。SSO 的原始认证时间保存在独立 Redis 元数据中，续期不重置认证时间，也不修改 SSO Token 的格式；元数据缺失或不满足 `max_age` 时重新认证。

### 8.3 密钥与迁移

`oidc.signing-key` 为至少 RSA-2048 的 PKCS#1/PKCS#8 私钥 PEM，可通过 `AEGIS_OIDC_SIGNING_KEY` 注入。缺失或无效时启动失败。新环境初始化生成独立 RSA-3072 密钥，所有服务副本使用同一配置。

签名配置在进程内缓存，修改或轮换后重启所有 Aegis 副本；先配置新私钥和旧公钥的组合，再等待旧 ID Token 过期后退役旧公钥。

`oidc.verification-keys` 为轮换公钥 PKIX PEM 列表，保留旧公钥直到旧 ID Token 全部过期。`kid` 使用 RFC 7638 RSA JWK thumbprint，现有 PASETO `/pubkeys` 与 PASERK 标识保持原样。

浏览器 SDK 使用 discovery/JWKS 验证 ID Token 的签名、issuer、client audience、到期时间和 nonce，在验证成功后提交登录状态。授权回调必须匹配保存的 state。前端用户字段迁移为标准 claim 名，时间按 Unix 秒解释。

Aegis、SDK 和前端消费者需协调发布；旧 PASETO ID Token 验证路径会被移除，业务 Access Token、CT 和 Refresh Token 保留现有契约。



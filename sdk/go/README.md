# hhub-risk-go

> hhub-risk 风控层的 Go SDK（Apache-2.0）。**只做本地验签与上下文注入**，判定永远在服务端。

## 安装

```bash
go get github.com/YU948136060/hhub-risk/sdk/go
```

## 三行接入

```go
import hhubrisk "github.com/YU948136060/hhub-risk/sdk/go"

mux := http.NewServeMux()
mux.Handle("/login", http.HandlerFunc(login))
handler := hhubrisk.Middleware(hhubrisk.Config{
    Secret: []byte(os.Getenv("RISK_SECRET")), // 与风控服务一致
})(mux)
```

需要硬拦时：

```go
hhubrisk.Config{Secret: secret, DenyOnMissing: true, DenyAtOrAbove: 70}
```

## 在业务里读分数

```go
claims, ok := hhubrisk.FromContext(r.Context())
if ok && claims.Risk >= 30 {
    // 要求人机验证 / 二次验证
}
```

## token 格式

```
v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256(secret, payload))>
```

与 Rust core、Python SDK 完全一致（跨语言测试向量见 `risk_test.go`，由
`cargo run --example sign_token` 生成）。

## 错误

- `ErrMalformed`：token 结构不对
- `ErrSignature`：签名/密钥不对
- 过期：`Verify` 仍返回 claims，用 `Claims.Valid(nowUnix)` 判断；中间件会当作无 token 处理

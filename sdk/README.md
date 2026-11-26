# SDK 一览

| 语言 | 目录 | 状态 | 说明 |
|---|---|---|---|
| Go | `sdk/go/` | ✅ 0.1 | 本地验签 + `http.Handler` 中间件（优先级 1） |
| Python | `sdk/python/` | ✅ 0.1 | 本地验签 + ASGI/WSGI 中间件（优先级 2） |
| Node | `sdk/node/` | ✅ 0.1 | 本地验签 + Express/Connect 中间件（优先级 3） |
| Java | `sdk/java/` | ✅ 0.1 | 零依赖验签 + Spring/Servlet 示例（优先级 4） |
| PHP | `sdk/php/` | ✅ 0.1 | 零依赖验签 + PSR-15 中间件（优先级 5；本机无 PHP，测试脚本待 CI 跑） |

全部 **Apache-2.0**；token 格式与后端 `core/`（AGPL-3.0）一致，跨语言测试向量统一由
`cargo run --example sign_token -- <secret> '<json>'` 生成并写进各语言测试。

## 一致的约定

- 请求头：`X-HHub-Risk: v1.<b64url(payload)>.<b64url(sig)>`
- claims：`{risk:0..100, action:"allow|challenge|step_up|deny", reasons:[...], exp, fp}`
- 没有 token：各 SDK 一律视为 `risk=100`，**默认放行但回写分数头**；硬拦需显式开启。

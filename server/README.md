# hhub-risk-server（参考实现）

> 故意**只用 std + serde_json**（不引 web 框架）：它的价值是让 SDK/前端对齐协议，
> 不是给你直接上生产。生产替换项见文末。

## 跑起来

```bash
RISK_SECRET=change-me cargo run -p hhub-risk-server
# hhub-risk reference server on http://127.0.0.1:8090
```

多实例（挑战必须共享，否则 A 发的挑战 B 不认）：

```bash
RISK_REDIS=redis://127.0.0.1:6379/0 RISK_SECRET=change-me RISK_LISTEN=127.0.0.1:8091 \
  cargo run -p hhub-risk-server &
RISK_REDIS=redis://127.0.0.1:6379/0 RISK_SECRET=change-me RISK_LISTEN=127.0.0.1:8093 \
  cargo run -p hhub-risk-server &
python3 server/tests/multi_instance.py     # PASS=5
```

- 挑战：`SETEX risk:ch:<id> 120 "<challenge>|<mix>"`，验证时 `GET` + `DEL`（一次性）；
- 限流：按 IP 固定窗口，`/v1/challenge` 30/min、`/v1/attest` 20/min，超限 429；
- 没配 `RISK_REDIS` 时用内存（单实例/测试），启动日志会明确写"内存（单实例）"。

## Docker / compose 三分钟跑通

```bash
docker compose up --build
# 风控服务 http://localhost:8090/healthz
# 示例页   http://localhost:8092  （页面 + /v1 反代 + 演示按钮）
```

`docker-compose.yml` 起三个容器：`redis`、`risk`（本服务，Redis 共享挑战）、
`demo`（nginx：静态示例页 + `/v1` 反代）。

> ⚠️ 本机实测：Dockerfile 与 compose 配置通过 `docker compose config` 校验，
> 但镜像构建在这台机器上**没有跑完** —— 拉 `rust:1.83-slim` 只有约 16 KB/s（14MB 用了 ~15 分钟），
> 属于网络限速，不是构建脚本问题。CI 或正常网络下 `docker compose up --build` 即可。

## 协议

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/challenge` | 发挑战：`{challenge_id, challenge, mix, difficulty}`（内存 120s、一次性） |
| POST | `/v1/attest` | `{challenge_id, nonce, fp}` → 校验绑定熵的 PoW + 环境证据 → `{token, ttl, risk, reasons, strong}` |
| POST | `/v1/score` | `{fp, telemetry, geo_country?}` → `{risk, action, reasons}` |
| GET | `/v1/verify?token=…` | 本地验签 token → `{valid, claims}` |
| GET | `/healthz` | 健康检查 |

token = `v1.<b64url(payload)>.<b64url(hmac_sha256(secret, payload))>`，
与 `core/` 及五种语言 SDK 完全一致。

PoW 材料（客户端/服务端必须逐字节一致）：

```
sha256( challenge | mix | canvas | round(raf_ms*10) | nonce )  前缀 difficulty 个 0
```

## 端到端冒烟

```bash
RISK_SECRET=test-secret RISK_LISTEN=127.0.0.1:8090 cargo run -q -p hhub-risk-server &
RISK_BASE=http://127.0.0.1:8090 python3 server/tests/smoke.py   # PASS=11
```

冒烟会用 Python SDK 验签服务端签出的 token，所以它同时验证了**跨语言协议一致**。

## 生产替换清单

- 挑战存储：内存 `Mutex<HashMap>` → Redis（多实例必须共享，否则挑战在别的实例上不存在）；
- IP 地理：本实现只接受调用方传入的 `geo_country` → 接 MaxMind/ip-api；
- 限流：本实现没有 → 按 IP 限制 `/v1/challenge`、`/v1/attest`；
- TLS：明文 HTTP，前面必须挂反代；
- 行为画像（L4）：本实现没有 → 属于站点特有层，不在开源仓库里。

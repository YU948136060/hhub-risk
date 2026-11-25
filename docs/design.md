# 风控系统：设计 + 开源接入（草案 2026-11-24）

> 目标（用户原话归纳）：
> 1. 不只判断"是不是人"，还要判断**这次访问对本站有没有风险**；
> 2. 白箱开源（**AGPL v3**）也要有效；
> 3. **接入必须非常轻松**：多种后端语言 + 多种前端框架，简单几行接上原生 JS；
> 4. 无痕模式是真实痛点：**无 session 时不要在无痕里注册出 master session**。
>
> 本文是设计与取舍记录，代码落地按 §9 的里程碑推进。当前已上线的部分（浏览器见证 + 行为评分）见
> [`9-人机验证-浏览器见证与行为风控.md`](9-人机验证-浏览器见证与行为风控.md)。

---

## 1. 分层：把"信号"和"决策"分开

```
浏览器 SDK (hhub-risk.js)                服务端 (risk-core)
┌──────────────────────────┐            ┌───────────────────────────────┐
│ L1 环境：canvas/WebGL/rAF │            │ ① 校验 PoW（绑定浏览器熵）      │
│     UA/屏幕/时区/语言      │  ──►       │ ② 打分：L1~L5 → risk 0..100    │
│ L2 行为：指针/触摸/按键/  │  attest    │ ③ 决策：allow / challenge /    │
│     停留/改选/看视频      │  ──►       │        deny / need-email-code  │
│ L3 网络：交给服务端看 IP   │            │ ④ 记忆：指纹/IP/账号 的历史     │
└──────────────────────────┘            └───────────────────────────────┘
```

**关键原则**：客户端只负责**采集**（可伪造，所以只当"降价信号"）；一切**判定**在服务端；
服务端所有阈值都写进配置与文档，白箱也能看懂，但**改不了**判定权。

---

## 2. 信号清单（现在有哪些、还要哪些）

| 层 | 信号 | 现状 | 用途 |
|---|---|---|---|
| L1 | canvas 光栅化哈希、WebGL vendor/renderer、rAF 时序、屏幕、时区、语言、UA 一致性 | ✅ 已上线 | 区分"浏览器 / 协议脚本"；指纹分桶限流 |
| L1 | **无痕模式**（见 §4） | ⬜ 待做 | 阻止无 session 的无痕注册 |
| L2 | 指针/触摸/按键、停留、改选、视频观看 | ✅ 已上线 | 区分"人 / 自动化" |
| L3 | IP → 国家/省/市（`session::lookup_geo`，Redis 缓存 30 天，ip-api.com） | ✅ 已有能力 | 地域风险 |
| L3 | 时区 ↔ IP 地理的一致性（如 IP=美国、`tz=Asia/Shanghai`） | ⬜ 待做 | 代理识别 |
| L3 | 语言 ↔ IP 地理（`Accept-Language: zh-CN` + IP 在美国） | ⬜ 待做 | 代理识别（弱信号） |
| L3 | 代理头/机房 ASN/UA 异常 | 部分（`ip_quality`） | 低质 IP → 加 PoW |
| L4 | 历史：同指纹/同 IP 的请求节奏、活跃时段、通过率、失败率 | 部分（配额/失败计数） | 长期画像 |
| L4 | **"声称时区"与"实际活跃时段"的长期矛盾**（见 §3） | ⬜ 待做 | 用户设想的极端场景 |
| L5 | 新设备 / 无主设备会话 / 会话时长 / 账号年龄 | 部分（第 15 条 2FA） | 账号风险 |

---

## 3. 用户设想的场景，怎么落地

> 「中国人用美国节点访问，但活跃在美国时间的白天，而且多天反应迟钝 ⇒ 很可能白天在用代理。」

可计算化：

1. 每次请求记录 `(指纹, IP, geo, utc_hour, tz_claimed, tz_offset)`；
2. 定义 **`tz_ip_mismatch`**：`|utc_offset(claimed_tz) - utc_offset(geo_tz)| ≥ 4h`；
3. 定义 **`active_in_geo_daytime`**：该指纹的请求里有 ≥60% 落在 `geo` 当地 08:00–20:00；
4. 组合规则（示例，阈值可配）：
   - `mismatch` 且 `active_in_geo_daytime` 且 `mismatch_days ≥ 3` ⇒ **risk +35**；
   - `mismatch` 单日 ⇒ +10（可能只是出差/旅行）；
   - `claimed tz` 与该用户**历史稳定 tz** 不同 ⇒ +15（换城市/换代理）。
5. 决策：risk ≥ 70 → 要求额外验证（邮箱码/更高难度 PoW）；≥ 85 → 拒绝并提示。
6. **不做的事**：不因为"IP 在美国"就直接判定风险（留学生、出差、VPN 都是正常需求），
   只看"长期、系统性的自相矛盾"。

> 需要的数据：一张按指纹聚合的日表（Redis Hash / PG 表），字段：`tz_hist`, `geo_hist`,
> `hour_hist[24]`, `mismatch_days`, `last_seen`。这属于"风控画像"，**不存内容、只存计数**。

---

## 4. 无痕模式：能做多少、怎么做

**坏消息**：浏览器**没有**标准的 `isIncognito()`。所有方法都是启发式，且会误伤
（Firefox 隐私窗口、Brave、Safari 隐私浏览各不相同）。

**可用的启发式**（组合使用，只在"高度确信"时才拦）：

| 信号 | 说明 |
|---|---|
| `navigator.storage.estimate()` 配额异常小 | Chrome 无痕的配额明显小于普通模式（经验值，需实测校准） |
| IndexedDB / CacheStorage 写入后立即不可用 | 部分隐私模式禁用 |
| `webkitTemporaryStorage` 存在但配额为 0 | 老 Safari 隐私模式 |
| 首次访问就把 `localStorage` 判为"已满" | 某些模式下写入即拒 |
| `navigator.storage.persisted()` 恒 false | 弱信号，普通模式也常见 |

**建议的三种档位**（需要用户拍板）：

| 档 | 行为 | 风险 |
|---|---|---|
| A（严格，用户原话） | 判定为无痕 + 无 session ⇒ **禁止注册 / 禁止创建 master session**，并给出提示 | 误伤 Firefox/Brave 隐私窗口的正常用户 |
| B（推荐） | 判定为无痕 ⇒ **警告 + 要求邮箱验证码**（或显示一次性恢复码）后才允许创建 master session | 多一步操作，但"无痕关了也能找回" |
| C（最松） | 只警告、不拦 | 用户的恐惧（会话丢失）依然存在 |

> 无论哪档，**必须**给一条找回路径（邮箱验证码 / 恢复码），否则用户真的会很痛苦。
> 另外：`Secure`/`SameSite` 之外，给 master session cookie 设置合理 `Max-Age` 并
> **在注册成功页明确告知"不要在无痕窗口注册"**，比什么检测都管用。

---

## 5. 打分与决策

```text
risk = 基础分(50)
     + Σ 规则加分（每条带 id、可解释、可关）
     - Σ 可信减分（长期稳定指纹/稳定 geo/多次通过）
clamp(0, 100)

risk < 30   → allow
30..69      → challenge（当前验证码；低分再加 PoW 难度）
70..84      → challenge + 要求邮箱码（step-up）
≥ 85        → deny（给明确文案 + 申诉入口）
```

**可解释性**：每次决策返回 `reasons: ["tz_ip_mismatch", "incognito_suspected", ...]`，
既方便运营排查，也让开源用户能自己改规则。

---

## 6. 开源接入（AGPL v3）

### 6.1 仓库结构（计划）

```
risk/
  core/            # Rust：信号打分/决策/存储（可独立 crate）
  server/          # 参考 HTTP 服务（axum）+ OpenAPI
  web/
    hhub-risk.js   # 零依赖原生 JS（UMD + ESM 双产物），约 30KB
    adapters/      # react/ vue/ svelte/ web-component（都是薄壳）
  sdk/
    node/ python/ go/ php/ java/   # 各 200 行左右的中间件 + 示例
  examples/
  LICENSE          # AGPL-3.0
```

### 6.2 稳定 HTTP 契约（任何后端都能实现/对接）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/challenge` | 发挑战：`{challenge_id, challenge, mix, difficulty}` |
| POST | `/v1/attest` | 交 PoW + 环境：`{challenge_id, nonce, fp}` → `{token, ttl}`（HMAC 签名） |
| POST | `/v1/score` | 交行为遥测 → `{risk, reasons, action}` |
| POST | `/v1/verify` | 校验 token（供业务后端调用，含 IP/geo 上下文） |

Token 用 HMAC-SHA256 签名，**任何语言都能本地验签**，不需要回调。

### 6.3 前端接入（三行）

```html
<script src="/risk/hhub-risk.js"></script>
<script>
  HHubRisk.mount('#risk-slot', { endpoint: '/risk' });   // 自动接管表单提交
</script>
```

框架薄壳：

```jsx
<HHubRisk endpoint="/risk" onVerified={...} />                    // React
<hhub-risk endpoint="/risk" @verified="..."></hhub-risk>          // Vue / Web Component
```

### 6.4 后端接入（以 Express 为例）

```js
app.use(HHubRisk.middleware({ endpoint: '/risk', protect: ['/login', '/register'] }));
```

Python（FastAPI/Flask 中间件）、Go（`http.Handler` 包装）、PHP（前置 filter）、
Java（Servlet Filter）形态一致：**读取 `X-HHub-Risk` 请求头 → 本地验签 → 得到风险分与决策**。

### 6.5 白箱也要有效：靠什么

1. 判定在服务端，客户端只能采集，**改不了分数**；
2. PoW 绑定浏览器熵（已实现）：换指纹/换会话都要重算；
3. 历史画像（L4）在服务端，攻击者看不到自己的画像，也就无法"对着规则调参"；
4. 阈值、规则 id 开源，但**历史数据、IP 库、密钥**不开源 —— 这是"白箱≠全透明"的分界线。

---

## 7. 与现有代码的关系

- 现有 `captcha_attest`（见证）、`captcha_risk`（行为评分）、`session::lookup_geo`（地理）
  正好对应 L1/L2/L3 的雏形，可以直接演进成 `risk/core`；
- 第 15 条已经有的"设备待审批 / 主设备"概念，是 L5 的基础，不需要另起炉灶。

---

## 8. 未决问题（需要拍板）

1. **无痕档位**：A 严格禁止 / B 警告+邮箱码（推荐）/ C 只警告？
2. **IP 地理数据源**：继续 ip-api.com（简单、有速率限制、境外），还是内置 `ip2region`/MaxMind
   （离线、无外呼、可商用授权要确认）？
3. **SDK 优先级**：Node + Python + Go 先行？PHP/Java 之后？
4. **仓库形态**：现在就把 `risk/` 抽成独立 crate/目录（便于将来单独发 AGPL 仓库），
   还是先长在 `hhub-server` 里、开源时再抽？

---

## 9. 里程碑

| # | 内容 | 状态 |
|---|---|---|
| M1 | L1+L2：浏览器见证 + 行为评分 + 绑定熵的 PoW | ✅ 已完成 |
| M2 | L3：时区/IP/语言一致性 + `reasons` 可解释输出 | ⬜ 下一轮 |
| M3 | L4：指纹/IP 日表 + 长期矛盾规则（§3） | ⬜ |
| M4 | 无痕检测 + 注册闸门（按 §4 选中档位） | ⬜ |
| M5 | 抽 `risk/` + HTTP 契约 + 前端 JS + 3 个后端 SDK + AGPL 头 | ⬜ |

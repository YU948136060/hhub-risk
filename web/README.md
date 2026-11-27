# hhub-risk-web

> 前端 SDK（Apache-2.0，**零依赖**，约 10KB）。它只负责采集环境、解绑定熵的 PoW、
> 把服务端签发的 token 放进请求头——**判定永远在服务端**。

## 三行接入

```html
<script src="/risk/hhub-risk.js"></script>
<script>
  HHubRisk.init({ endpoint: 'https://risk.example.com' });
</script>
```

之后业务请求用 `HHubRisk.fetch()`，会自动带 `X-HHub-Risk`：

```js
const r = await HHubRisk.fetch('/login', { method: 'POST', body: form });
```

可选：

```js
const token = await HHubRisk.ready();
HHubRisk.last();                       // { risk, reasons, pow, strong }
await HHubRisk.score({ pointer: 12, keys: 0, corrections: 1, dwell_ms: 4000,
                       video_ms: 2500, visible: true });
```

## 框架薄壳（`web/adapters/`）

- **React**：`<HHubRisk endpoint="…" onReady={…}>{(s) => …}</HHubRisk>`
- **Vue 3**：`app.use(HHubRiskPlugin, { endpoint })` → 组件里 `inject('hhubRisk')`
- **Web Component**：`<hhub-risk endpoint="…">`，监听 `hhub-risk-ready` / `hhub-risk-error`

三者都是几十行的薄壳，逻辑全部复用 `hhub-risk.js`。

## 测试

单测（纯逻辑）：

```bash
node --test web/test/
# 3 passed：SHA-256 与 node:crypto 一致、PoW 材料量化一致、无 DOM 环境降级不抛错
```

**真浏览器端到端**（需要参考服务器在跑）：

```bash
RISK_SERVER=http://127.0.0.1:8091 RISK_SECRET=test-secret \
  node web/test/browser-smoke.mjs
# 浏览器拿到 token；risk=65 PoW=10299次/204ms
# Python SDK 验签通过
# PASS
```

脚本会起一个同源 fixture（页面 + SDK + `/v1/*` 代理），用 headless Chrome 真跑一遍
canvas/WebGL/rAF → PoW → attest，最后用 **Python SDK** 验签 token。

## 边界

- 采集的东西都可以被伪造，它只抬高成本；
- 私密模式目前只是 `fp.private` 的一个启发式标记（localStorage 写入失败 / 无 IndexedDB）；
- 老浏览器没有 `Pointer Events` 时，触摸计数由业务侧的行为遥测补（见本站实现）。

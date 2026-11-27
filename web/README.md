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

```bash
node --test web/test/
# 3 passed：SHA-256 与 node:crypto 一致、PoW 材料量化一致、无 DOM 环境降级不抛错
```

## 边界

- 采集的东西都可以被伪造，它只抬高成本；
- 私密模式目前只是 `fp.private` 的一个启发式标记（localStorage 写入失败 / 无 IndexedDB）；
- 老浏览器没有 `Pointer Events` 时，触摸计数由业务侧的行为遥测补（见本站实现）。

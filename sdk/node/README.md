# hhub-risk-node

> hhub-risk 风控层 Node SDK（Apache-2.0）。本地验签 + Express/Connect 中间件。

```js
import hhubrisk from 'hhub-risk';   // 或从仓库路径引用

app.use(hhubrisk.middleware({ secret: process.env.RISK_SECRET, denyAtOrAbove: 70 }));
app.post('/login', (req, res) => {
  if (req.risk.risk >= 30) { /* 要求人机验证 */ }
});
```

无 token 时 `req.risk.risk = 100`，默认**不拦**；要硬拦传 `denyOnMissing: true`。

token 格式与 Rust core / Go / Python 一致；测试向量同源。

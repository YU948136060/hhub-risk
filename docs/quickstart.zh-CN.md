# 快速开始（规划中）

> 当前仓库只有 `core/`；下面这份是**目标形态**，`server/` 与 SDK 落地后按此执行。

## 1. 起服务

```bash
docker run -p 8080:8080 -e RISK_SECRET=change-me ghcr.io/<org>/hhub-risk
```

## 2. 前端

```html
<script src="https://risk.example.com/hhub-risk.js"></script>
<script>
  HHubRisk.mount('#risk-slot', { endpoint: 'https://risk.example.com' });
</script>
```

## 3. 后端（Go，第一优先）

```go
import "github.com/<org>/hhub-risk-go"

h := hhubrisk.New(hhubrisk.Config{Secret: os.Getenv("RISK_SECRET")})
http.Handle("/", h.Protect("/login", "/register", next))
```

## 4. 判定

服务端返回：

```json
{ "risk": 42, "action": "challenge", "reasons": ["behavior:ok", "tz_geo_mismatch:12h"] }
```

`action` ∈ `allow | challenge | step_up | deny`，阈值见 `core::decide`。

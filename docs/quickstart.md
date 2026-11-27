# Quickstart

> Right now the repo ships `core/`, `server/`, `web/` and five SDKs.
> The steps below are the intended integration shape.

## 1. Run the server

```bash
# Docker (server + Redis + demo page)
docker compose up --build
# demo: http://localhost:8092    service: http://localhost:8090/healthz

# …or from source
RISK_SECRET=change-me cargo run -p hhub-risk-server
```

Multi-instance (challenges must be shared):

```bash
RISK_REDIS=redis://127.0.0.1:6379/0 RISK_SECRET=change-me RISK_LISTEN=127.0.0.1:8091 \
  cargo run -p hhub-risk-server &
```

## 2. Frontend (three lines)

```html
<script src="/risk/hhub-risk.js"></script>
<script>
  HHubRisk.init({ endpoint: '' });        // same origin; or https://risk.example.com
</script>
```

All following requests may use `HHubRisk.fetch()` — it attaches `X-HHub-Risk` automatically.

## 3. Backend (Go)

```go
import hhubrisk "github.com/YU948136060/hhub-risk/sdk/go"

handler := hhubrisk.Middleware(hhubrisk.Config{Secret: secret, DenyAtOrAbove: 70})(mux)
claims, ok := hhubrisk.FromContext(r.Context())
```

Python / Node / Java / PHP are symmetric — see `sdk/*/README.md`.

## 4. Interpret the decision

```json
{ "risk": 42, "action": "challenge", "reasons": ["behavior:ok", "tz_geo_mismatch:12h"] }
```

`action` ∈ `allow | challenge | step_up | deny`; thresholds live in `core::decide`
and can be tuned by the host application.

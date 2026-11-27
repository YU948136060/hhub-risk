# hhub-risk

> **A self-hosted risk layer for social platforms**: browser attestation, behaviour scoring,
> IP/geo consistency, and a pluggable captcha — with all decisions made server-side.
>
> **[中文](README.zh-CN.md)** · **English**

## Why

Self-hosted social platforms usually get two choices: embed a closed-source captcha
(user data leaves your server), or do nothing (and drown in signup bots).

This project aims at a third option:

- your data never leaves your server;
- **decisions live on the server**, the client only collects signals (therefore open source still works);
- the captcha is **pluggable** (bring ALTCHA / Cap / Turnstile if you like);
- integration is measured in *lines*, not in *days of reading docs*.

## Status

| Layer | What | Status |
|---|---|---|
| L1 Browser attestation | canvas / WebGL / rAF timing / UA consistency + PoW bound to those signals | ✅ production in HHub |
| L2 Behaviour scoring | pointer / touch / keys / dwell / corrections / video → 0–100 | ✅ production in HHub |
| L3 Network & geo | IP → country/city; timezone/language consistency | ✅ production in HHub |
| L4 Long-term profile | per-fingerprint history, rhythm, rotation, template reuse | ✅ production (rules themselves are **not** open source) |
| L5 Account/session | new device, private window, master session | ✅ production (email step-up) |
| Protocol | `/v1/challenge`, `/v1/attest`, `/v1/score`, `/v1/verify` | ✅ reference server + OpenAPI |
| Clients | zero-dependency `hhub-risk.js` + React/Vue/WebComponent shells | ✅ browser end-to-end smoke |
| SDKs | Go, Python, Node, Java, PHP (local token verification) | ✅ same cross-language test vector |

## Three-minute quickstart (Docker)

```bash
docker compose up --build
# demo page     http://localhost:8092   ← click the button
# risk service  http://localhost:8090/healthz
```

## Repo layout

```
core/            Rust crate: scoring, decisions, HMAC token (no IO)
server/          reference HTTP service (std + serde_json) + OpenAPI
web/             frontend SDK (zero deps) + React / Vue / Web Component shells
sdk/{go,python,node,java,php}/   local token verification + middleware
examples/demo/   demo page + nginx reverse proxy for docker compose
deploy/          nginx / deployment notes
LICENSE-AGPL-3.0 / LICENSE-APACHE-2.0
```

## Docs

- [Quickstart](docs/quickstart.md) · [快速开始](docs/quickstart.zh-CN.md)
- [Design](docs/design.md) · [设计](docs/design.zh-CN.md)
- Hosted docs: <https://risk.hydrogen-ion.top:8888>

## License

| Part | License | Why |
|---|---|---|
| `core/`, `server/` | **AGPL-3.0** | the decision engine; AGPL keeps improvements public while still allowing closed-source deployments |
| `web/`, `sdk/*` | **Apache-2.0** | SDKs are independent HTTP clients (no linking), and Apache-2.0 carries a patent grant |

Apache-2.0 and GPLv3/AGPLv3 are compatible (FSF), so Apache SDKs may be distributed alongside
the AGPL server; the reverse is **not** allowed. Every source file carries an SPDX header.

## Boundary

- Open source: the generic layer — captcha, PoW, browser attestation, IP geo, scoring framework.
- **Not** open source: site-specific rules for social platforms (signup farms, spam, fake engagement).
  This repository intentionally contains only the **interface** (`Rule`) and scenario hints.

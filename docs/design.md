# Design

> Generic layer: **browser attestation + behaviour scoring + network/geo consistency + pluggable captcha**.
> All decisions happen on the server; the client only collects signals.

![Architecture](../arch.svg)

## 1. Layers

```
browser SDK                             risk server
┌──────────────────────────┐            ┌───────────────────────────────┐
│ L1 env: canvas/WebGL/rAF │            │ ① verify PoW (bound to entropy)│
│    UA / screen / tz/lang │  ──►       │ ② score L1..L5 → risk 0..100   │
│ L2 behaviour: pointer/   │  attest    │ ③ decide: allow / challenge /  │
│    touch/keys/dwell/video│  ──►       │        step_up / deny          │
│ L3 network: server-side  │            │ ④ remember (fingerprint/IP)    │
└──────────────────────────┘            └───────────────────────────────┘
```

Principle: the client only **collects** (everything can be forged, so it only adds friction);
every decision is server-side. Rules and thresholds are documented — white-box, still effective.

## 2. Signals

| Layer | Signal | Use |
|---|---|---|
| L1 | canvas raster hash, WebGL vendor/renderer, rAF timing, screen, timezone, language, UA consistency | tell browsers from protocol clients; fingerprint buckets |
| L1 | private/incognito heuristics | gate master-session creation (email step-up) |
| L2 | pointer/touch/keys, dwell, corrections, video watched | tell humans from automation |
| L3 | IP → country/city (cached); timezone ↔ IP-country mismatch; language ↔ geo | proxy detection (weak signal only) |
| L4 | per-fingerprint history: rhythm, subnet/country rotation, template reuse, post-signup burst | long-term profiling (site-specific rules, not open source) |
| L5 | new device, no primary session | account-level risk |

## 3. Scoring & decisions

```
risk = 50 + Σ rule scores − Σ trust bonuses      (clamped 0..100)

risk < 30   → allow
30..69      → challenge   (captcha; low score may raise PoW difficulty)
70..84      → step_up     (email code)
≥ 85        → deny
```

Every decision returns `reasons` (rule ids + facts), so operators and white-box users can
audit and tune.

## 4. PoW bound to browser entropy

```
material = challenge | mix | canvas | round(raf_ms*10)
sha256(material + nonce) has `difficulty` leading zero hex digits
```

Consequences: a solved PoW cannot be replayed with another fingerprint; bots must recompute
per spoofed fingerprint. (Difficulty 3 ⇒ ~4k hashes; measured: 51–204 ms in a real browser.)

## 5. Private / incognito windows (plan B)

Browsers expose no standard `isIncognito()`. Strong heuristics only: localStorage write failure,
missing IndexedDB, `webkitTemporaryStorage` quota 0, `storage.estimate().quota < 50MB`.

- registration still requires an email code (recovery path exists);
- login **without a primary session and without 2FA** → email step-up before creating a master session;
- login with 2FA → existing TOTP step-up.

## 6. Integration contract

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/challenge` | issue `{challenge_id, challenge, mix, difficulty}` (120 s, single use) |
| POST | `/v1/attest` | verify bound PoW + environment evidence → `{token, ttl, risk, reasons}` |
| POST | `/v1/score` | behaviour telemetry → `{risk, action, reasons}` |
| GET | `/v1/verify?token=` | local signature verification |

Tokens: `v1.<b64url(payload)>.<b64url(hmac_sha256(secret, payload))>` — any language can verify
locally; the five SDKs share one cross-language test vector.

## 7. Licensing

- `core/`, `server/`: **AGPL-3.0**;
- `web/`, `sdk/*`: **Apache-2.0** (independent HTTP clients, no linking).

## 8. Boundaries

- Does **not** stop a full browser automation stack (Playwright). Behaviour signals raise the cost only.
- Do not judge "IP is abroad" as risk by itself; only long-term, systematic contradictions.
- Site-specific social-platform rules stay out of this repository; only the `Rule` trait and
  scenario hints are published.

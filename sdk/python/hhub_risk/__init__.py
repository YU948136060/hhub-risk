# SPDX-License-Identifier: Apache-2.0
"""hhub-risk Python SDK（Apache-2.0）。

设计前提：所有判定在服务端。本 SDK 只做两件事：

1. `verify()`：本地验签风控服务下发的 token（HMAC-SHA256，无需回调）；
2. `ASGIMiddleware` / `WSGIMiddleware`：把 claims 放进 request.state / environ。

token 格式与 Rust core、Go SDK 一致：

    v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256(secret, payload))>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

__all__ = ["verify", "Claims", "ASGIMiddleware", "WSGIMiddleware", "HEADER"]

HEADER = "x-hhub-risk"

ACTION_ALLOW = "allow"
ACTION_CHALLENGE = "challenge"
ACTION_STEP_UP = "step_up"
ACTION_DENY = "deny"


class Claims(dict):
    """token 载荷（dict 子类，方便直接用 `claims["risk"]`）。"""

    @property
    def risk(self) -> int:
        return int(self.get("risk", 100))

    @property
    def action(self) -> str:
        return str(self.get("action", ACTION_DENY))

    def valid(self, now: float | None = None) -> bool:
        exp = int(self.get("exp", 0) or 0)
        if not exp:
            return True
        return (time.time() if now is None else now) < exp


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def verify(secret: str | bytes, token: str) -> Claims | None:
    """验签成功返回 Claims，失败返回 None（不区分"结构错"与"签名错"，避免探测）。"""
    if not secret or not token:
        return None
    if isinstance(secret, str):
        secret = secret.encode()
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        return None
    try:
        body = _b64d(parts[1])
        sig = _b64d(parts[2])
    except Exception:
        return None
    want = hmac.new(secret, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, want):
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    return Claims(data) if isinstance(data, dict) else None


def _claims_from_header(header_value: str | None, secret: str | bytes) -> Claims:
    """没有/无效 token 时返回 risk=100 的"最坏情况"，但**不**替业务做决定。"""
    c = verify(secret, header_value or "")
    if c is None:
        return Claims({"risk": 100, "action": ACTION_DENY, "reasons": ["missing_or_bad_token"]})
    return c


class ASGIMiddleware:
    """FastAPI/Starlette 可用：`app.add_middleware(ASGIMiddleware, secret=...)`。

    注入 `request.state.risk`（Claims）。需要硬拦时传 `deny_at_or_above`。
    """

    def __init__(self, app, secret: str | bytes, deny_at_or_above: int | None = None):
        self.app = app
        self.secret = secret
        self.deny_at_or_above = deny_at_or_above

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        claims = _claims_from_header(headers.get(HEADER), self.secret)
        scope.setdefault("state", {})["risk"] = claims
        if self.deny_at_or_above is not None and claims.risk >= self.deny_at_or_above:
            body = json.dumps(
                {"error": "请求被风控拦截", "risk": claims.risk,
                 "action": claims.action, "reasons": claims.get("reasons", [])},
                ensure_ascii=False,
            ).encode()
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json; charset=utf-8"),
                                    (b"x-hhub-risk-score", str(claims.risk).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        return await self.app(scope, receive, send)


class WSGIMiddleware:
    """Flask/Django 可用：包一层 `app.wsgi_app`。claims 放进 `environ["hhub.risk"]`。"""

    def __init__(self, app, secret: str | bytes, deny_at_or_above: int | None = None):
        self.app = app
        self.secret = secret
        self.deny_at_or_above = deny_at_or_above

    def __call__(self, environ, start_response):
        header = environ.get("HTTP_X_HHUB_RISK", "")
        claims = _claims_from_header(header, self.secret)
        environ["hhub.risk"] = claims
        if self.deny_at_or_above is not None and claims.risk >= self.deny_at_or_above:
            body = json.dumps({"error": "请求被风控拦截", "risk": claims.risk}).encode()
            start_response("403 Forbidden", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("X-HHub-Risk-Score", str(claims.risk)),
            ])
            return [body]
        return self.app(environ, start_response)

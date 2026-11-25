// SPDX-License-Identifier: Apache-2.0
/**
 * hhub-risk Node SDK（Apache-2.0）。
 *
 * 设计前提：判定在服务端。这里只做两件事：
 *   1. verify()：本地验签（HMAC-SHA256），不需要回调；
 *   2. middleware()：Express/Koa/Connect 风格中间件，把 claims 挂到 req.risk。
 *
 * token 格式与 Rust core / Go / Python 一致：
 *   v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256(secret, payload))>
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

export const HEADER = 'x-hhub-risk';

/** 验签成功返回 claims，失败返回 null。 */
export function verify(secret, token) {
  if (!secret || !token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  let body, sig;
  try {
    body = Buffer.from(parts[1], 'base64url');
    sig = Buffer.from(parts[2], 'base64url');
  } catch {
    return null;
  }
  const want = createHmac('sha256', secret).update(body).digest();
  if (sig.length !== want.length || !timingSafeEqual(sig, want)) return null;
  try {
    const data = JSON.parse(body.toString('utf8'));
    return data && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
}

/** 过期判断：exp 为 0/缺省视为不过期。 */
export function valid(claims, nowMs = Date.now()) {
  const exp = Number(claims?.exp || 0);
  return !exp || nowMs / 1000 < exp;
}

/**
 * 中间件。用法：
 *   app.use(hhubrisk.middleware({ secret, denyAtOrAbove: 70 }));
 *
 * 行为：把 claims 挂到 `req.risk`；`denyAtOrAbove` 命中时直接 403 JSON。
 * 没有 token 时 risk=100（最坏情况），但**默认不拦**——除非传 denyOnMissing。
 */
export function middleware({ secret, header = HEADER, denyOnMissing = false, denyAtOrAbove = 0 } = {}) {
  return function hhubRisk(req, res, next) {
    const raw = req.headers?.[header] || req.headers?.[header.toLowerCase()] || '';
    let claims = { risk: 100, action: 'deny', reasons: ['missing_token'] };
    let ok = false;
    const c = verify(secret, raw);
    if (c && valid(c)) {
      claims = c;
      ok = true;
    } else if (c) {
      claims = { ...c, risk: 100, action: 'deny', reasons: ['expired'] };
    }
    req.risk = claims;
    if (typeof res.setHeader === 'function') res.setHeader('X-HHub-Risk-Score', String(claims.risk ?? 100));
    if (!ok && denyOnMissing) return deny(res, claims);
    if (ok && denyAtOrAbove > 0 && Number(claims.risk ?? 100) >= denyAtOrAbove) return deny(res, claims);
    return next();
  };
}

function deny(res, claims) {
  const body = JSON.stringify({
    error: '请求被风控拦截',
    risk: claims.risk ?? 100,
    action: claims.action ?? 'deny',
    reasons: claims.reasons ?? [],
  });
  if (typeof res.status === 'function') {
    res.status(403).type('application/json; charset=utf-8').send(body);
  } else {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(body);
  }
}

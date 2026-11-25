// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, valid, middleware } from '../index.js';

// 与 Rust core / Go / Python 共用的跨语言向量
const VECTOR = 'v1.eyJhY3Rpb24iOiJjaGFsbGVuZ2UiLCJleHAiOjQxMDI0NDQ4MDAsImZwIjoiYWJjIiwicmlzayI6NDJ9.'
  + 'Bg0XCR_JtF8muQbAt9td2o9WlNdxxs_8ZW9CtKIUF5o';
const SECRET = 'test-secret';

test('验证 Rust 生成的向量', () => {
  const c = verify(SECRET, VECTOR);
  assert.equal(c.risk, 42);
  assert.equal(c.action, 'challenge');
  assert.equal(c.fp, 'abc');
});

test('错密钥 / 篡改 / 结构错都失败', () => {
  assert.equal(verify('other', VECTOR), null);
  assert.equal(verify(SECRET, VECTOR.slice(0, -2) + 'aa'), null);
  assert.equal(verify(SECRET, VECTOR + 'x'), null);
  assert.equal(verify(SECRET, 'v2.a.b'), null);
});

test('过期判断', () => {
  const c = verify(SECRET, VECTOR);
  assert.equal(valid(c, 4102444799 * 1000), true);
  assert.equal(valid(c, 4102444800 * 1000), false);
});

function run(mw, headers = {}) {
  const req = { headers };
  const res = {
    headers: {},
    statusCode: 200,
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    type() { return this; },
    send(body) { this.body = body; return this; },
  };
  let nexted = false;
  mw(req, res, () => { nexted = true; });
  return { req, res, nexted };
}

test('中间件注入 claims 并回写分数头', () => {
  const { req, res, nexted } = run(middleware({ secret: SECRET }), { 'x-hhub-risk': VECTOR });
  assert.equal(nexted, true);
  assert.equal(req.risk.risk, 42);
  assert.equal(res.headers['X-HHub-Risk-Score'], '42');
});

test('denyAtOrAbove 拦截', () => {
  const { res, nexted } = run(middleware({ secret: SECRET, denyAtOrAbove: 40 }), { 'x-hhub-risk': VECTOR });
  assert.equal(nexted, false);
  assert.equal(res.statusCode, 403);
  assert.match(res.body, /风控/);
});

test('缺 token 默认放行但 risk=100；denyOnMissing 时 403', () => {
  const a = run(middleware({ secret: SECRET }), {});
  assert.equal(a.nexted, true);
  assert.equal(a.req.risk.risk, 100);
  const b = run(middleware({ secret: SECRET, denyOnMissing: true }), {});
  assert.equal(b.nexted, false);
  assert.equal(b.res.statusCode, 403);
});

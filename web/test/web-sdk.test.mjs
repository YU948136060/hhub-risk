// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';

const src = readFileSync(new URL('../hhub-risk.js', import.meta.url), 'utf8');

/** 在最小假 DOM 里加载 UMD，拿到 __test 导出。 */
function loadSdk() {
  const sandbox = {
    console,
    setTimeout,
    performance,
    TextEncoder,
    Uint8Array,
    Math,
    document: {
      createElement: () => ({ getContext: () => null, width: 0, height: 0 }),
    },
    navigator: { userAgent: 'test', language: 'zh-CN' },
    screen: { width: 1, height: 1, colorDepth: 24 },
    window: {},
    localStorage: { setItem() {}, removeItem() {} },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(src, ctx);
  return ctx.HHubRisk;
}

test('纯 JS SHA-256 与 node:crypto 一致', () => {
  const sdk = loadSdk();
  for (const s of ['', 'abc', 'a'.repeat(55), '风控 2026', 'x'.repeat(200)]) {
    const ref = createHash('sha256').update(s).digest('hex');
    assert.equal(sdk.__test.sha256hex(s), ref, `输入长度 ${s.length}`);
  }
});

test('PoW 材料与服务端口径一致', () => {
  const sdk = loadSdk();
  // raf_ms 量化到 10ms：333.44 与 333.41 必须同串
  assert.equal(
    sdk.__test.powMaterial('c', 'm', 'canvas', 333.44),
    sdk.__test.powMaterial('c', 'm', 'canvas', 333.41),
  );
  assert.equal(sdk.__test.powMaterial('c', 'm', 'x', 100), 'c|m|x|1000');
});

test('无 DOM 环境下采集降级而不抛错', () => {
  const sdk = loadSdk();
  const fp = sdk.__test.collectFp({ raf: 0, raf_ms: 0 });
  assert.equal(fp.canvas, '');
  assert.equal(fp.webgl, '');
  assert.equal(fp.screen, '1x1x24');
});

// SPDX-License-Identifier: Apache-2.0
/**
 * 浏览器端到端冒烟：真实浏览器加载 `web/hhub-risk.js`，走完
 * challenge → 绑定熵的 PoW → /v1/attest → token，最后用 **Python SDK** 验签。
 *
 * 为什么需要它：单测只能证明 SHA-256/材料拼法正确，证明不了
 * "在真浏览器的 canvas/WebGL/rAF 下也能拿到 token"。
 *
 * 用法：
 *   RISK_SERVER=http://127.0.0.1:8091 RISK_SECRET=test-secret \
 *     node web/test/browser-smoke.mjs
 *
 * 前置：参考服务器在跑（`cargo run -p hhub-risk-server`）。
 */
import http from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SDK = path.resolve(HERE, '..', 'hhub-risk.js');
const RISK_SERVER = process.env.RISK_SERVER || 'http://127.0.0.1:8091';
const SECRET = process.env.RISK_SECRET || 'test-secret';
const PORT = Number(process.env.FIXTURE_PORT || 8092);

function findChrome() {
  const cands = [
    process.env.CHROME,
    '/home/heavenly-hound/HHub/hdd/ab-home/.agent-browser/browsers',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
  ].filter(Boolean);
  for (const c of cands) {
    if (c.endsWith('/chrome') && existsSync(c)) return c;
    if (!existsSync(c)) continue;
    // 目录：找 <dir>/chrome-*/chrome
    try {
      for (const d of readdirSync(c)) {
        const p = path.join(c, d, 'chrome');
        if (existsSync(p)) return p;
      }
    } catch { /* ignore */ }
  }
  return '';
}

const HTML = `<!doctype html><meta charset="utf-8"><title>risk smoke</title>
<script src="/hhub-risk.js"></script>
<script>
  window.__res = null;
  HHubRisk.init({ endpoint: '' })
    .then(function (token) {
      window.__res = { ok: true, token: token, risk: HHubRisk.last().risk,
                       reasons: HHubRisk.last().reasons, pow: HHubRisk.last().pow };
    })
    .catch(function (e) {
      window.__res = { ok: false, error: String(e && e.message) };
    });
</script>`;

/** 同源 fixture：页面 + SDK + 把 /v1/* 代理到参考服务器（避免 CORS）。 */
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(HTML);
    return;
  }
  if (req.url === '/hhub-risk.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(readFileSync(SDK));
    return;
  }
  if (req.url.startsWith('/v1/')) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const up = new URL(RISK_SERVER);
      const r = http.request({
        host: up.hostname, port: up.port, path: req.url, method: req.method,
        headers: { 'Content-Type': 'application/json', 'Content-Length': body.length },
      }, (upr) => {
        const out = [];
        upr.on('data', (c) => out.push(c));
        upr.on('end', () => {
          res.writeHead(upr.statusCode || 500, { 'Content-Type': 'application/json' });
          res.end(Buffer.concat(out));
        });
      });
      r.on('error', (e) => { res.writeHead(502); res.end(JSON.stringify({ error: String(e) })); });
      r.end(body);
    });
    return;
  }
  res.writeHead(404); res.end('not found');
});

const chrome = findChrome();
if (!chrome) {
  console.log('⚠️ 没有找到 Chrome（设置 CHROME=/path/to/chrome）');
  process.exit(3);
}

const profile = mkdtempSync(path.join(tmpdir(), 'hhub-risk-chrome-'));
const child = spawn(chrome, [
  '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
  '--no-first-run', '--no-default-browser-check',
  `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank',
], { stdio: 'ignore' });

const cleanup = () => {
  try { child.kill('SIGKILL'); } catch { /* ignore */ }
  try { server.close(); } catch { /* ignore */ }
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* ignore */ }
};
process.on('exit', cleanup);
process.on('uncaughtException', (e) => { console.error(e); cleanup(); process.exit(1); });

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function devtoolsPort() {
  const file = path.join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100; i++) {
    if (existsSync(file)) {
      const txt = readFileSync(file, 'utf8').split('\n');
      if (txt[0]) return Number(txt[0]);
    }
    await sleep(100);
  }
  throw new Error('Chrome 没有写出 DevToolsActivePort');
}

class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map();
    ws.addEventListener('message', (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id);
        this.pending.delete(m.id);
        m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); reject(new Error('CDP 超时: ' + method)); } }, 30000);
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    return r.result?.value;
  }
}

const main = async () => {
  await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));
  const port = await devtoolsPort();
  const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const page = list.find((t) => t.type === 'page');
  if (!page) throw new Error('没有 page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  const cdp = new CDP(ws);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${PORT}/` });
  let res = null;
  for (let i = 0; i < 120; i++) {
    await sleep(250);
    res = await cdp.eval('window.__res');
    if (res) break;
  }
  if (!res || !res.ok) throw new Error('浏览器侧失败: ' + JSON.stringify(res));
  console.log('浏览器拿到 token；risk=' + res.risk + ' reasons=' + JSON.stringify(res.reasons) +
    ' PoW=' + res.pow.attempts + '次/' + res.pow.ms + 'ms');

  // 跨语言：用 Python SDK 验签这个 token
  const py = spawnSyncPython(res.token);
  if (py !== 'True') throw new Error('Python SDK 验签失败: ' + py);
  console.log('Python SDK 验签通过');
  console.log('PASS');
  cleanup();
  process.exit(0);
};

function spawnSyncPython(token) {
  const code = `import sys; sys.path.insert(0,'risk/sdk/python'); from hhub_risk import verify; print(bool(verify(sys.argv[1], sys.argv[2])))`;
  const r = spawnSync('python3', ['-c', code, SECRET, token], { cwd: path.resolve(HERE, '../../..'), encoding: 'utf8' });
  if (r.status !== 0) throw new Error('python3 失败: ' + (r.stderr || ''));
  return r.stdout.trim();
}

main().catch((e) => { console.error('[FAIL]', e.message); cleanup(); process.exit(1); });

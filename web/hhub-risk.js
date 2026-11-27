/* SPDX-License-Identifier: Apache-2.0 */
/*
 * hhub-risk 前端 SDK（零依赖，经典脚本；也兼容 CommonJS）。
 *
 * 三行接入：
 *   <script src="/risk/hhub-risk.js"></script>
 *   HHubRisk.init({ endpoint: 'https://risk.example.com' });
 *   HHubRisk.fetch('/login', {method:'POST', body})   // 自动带上 X-HHub-Risk
 *
 * 它做三件事：
 *   1. 采集浏览器环境指纹（canvas / WebGL / rAF 时序 / 屏幕 / 时区 / 语言）；
 *   2. 解一个**绑定这些熵**的 PoW（换指纹/换会话都要重算）；
 *   3. 把服务端签发的 token 放进请求头，供业务后端本地验签。
 *
 * 注意：判定永远在服务端。这里采集的一切都可以被伪造，它只负责抬高成本。
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) module.exports = factory();
    else root.HHubRisk = factory();
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    var cfg = { endpoint: '', header: 'X-HHub-Risk', token: '', inflight: null, last: null };

    // ── SHA-256（纯 JS，同步；用于 canvas 指纹与 PoW）──
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function sha256hex(str) {
        var bytes = new TextEncoder().encode(str);
        var l = bytes.length, n = Math.ceil((l + 9) / 64) * 16, m = new Uint8Array(n * 4);
        m.set(bytes);
        m[l] = 0x80;
        var bits = l * 8;
        m[n * 4 - 1] = bits & 0xff; m[n * 4 - 2] = (bits >>> 8) & 0xff;
        m[n * 4 - 3] = (bits >>> 16) & 0xff; m[n * 4 - 4] = (bits >>> 24) & 0xff;
        var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        var w = new Array(64);
        function rotr(x, k) { return (x >>> k) | (x << (32 - k)); }
        for (var i = 0; i < n; i += 16) {
            for (var t = 0; t < 16; t++) {
                var o = (i + t) * 4;
                w[t] = ((m[o] << 24) | (m[o + 1] << 16) | (m[o + 2] << 8) | m[o + 3]) | 0;
            }
            for (t = 16; t < 64; t++) {
                var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
                var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
                w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
            }
            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (t = 0; t < 64; t++) {
                var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                var ch = (e & f) ^ (~e & g);
                var t1 = (hh + S1 + ch + K[t] + w[t]) | 0;
                var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var t2 = (S0 + maj) | 0;
                hh = g; g = f; f = e; e = (d + t1) | 0;
                d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
            h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
        }
        var out = '';
        for (i = 0; i < 8; i++) out += ('00000000' + (h[i] >>> 0).toString(16)).slice(-8);
        return out;
    }

    // ── 环境采集 ──
    function canvasHash() {
        try {
            var c = document.createElement('canvas');
            c.width = 220; c.height = 48;
            var x = c.getContext('2d');
            if (!x) return '';
            x.fillStyle = '#f7f1e3'; x.fillRect(0, 0, 220, 48);
            var g = x.createLinearGradient(0, 0, 220, 48);
            g.addColorStop(0, '#c0392b'); g.addColorStop(0.53, '#27ae60'); g.addColorStop(1, '#2c3e50');
            x.fillStyle = g;
            x.font = '17px "Noto Sans CJK SC", "Microsoft YaHei", sans-serif';
            x.fillText('HHub risk 2026', 6, 21);
            x.fillText('\u98ce\u63a7 \u9a8c\u8bc1 0,1,2,3', 6, 41);
            x.strokeStyle = 'rgba(0,0,0,0.35)'; x.lineWidth = 1.5;
            x.beginPath(); x.arc(120, 24, 19, 0.2, 2.9); x.stroke();
            var d = x.getImageData(0, 0, 220, 48).data;
            var s = '';
            for (var i = 0; i < d.length; i += 97) s += String.fromCharCode(d[i]);
            return sha256hex(s);
        } catch (e) { return ''; }
    }

    function webglInfo() {
        try {
            var c = document.createElement('canvas');
            var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
            if (!gl) return '';
            var ext = gl.getExtension('WEBGL_debug_renderer_info');
            var v = ext ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)) : String(gl.getParameter(gl.VENDOR));
            var r = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : String(gl.getParameter(gl.RENDERER));
            return (v + '|' + r).slice(0, 200);
        } catch (e) { return ''; }
    }

    function rafTiming() {
        return new Promise(function (resolve) {
            var n = 0, t0 = performance.now();
            if (typeof requestAnimationFrame !== 'function') { resolve({ raf: 0, raf_ms: 0 }); return; }
            function step() {
                n++;
                if (n >= 20 || performance.now() - t0 > 900) {
                    resolve({ raf: n, raf_ms: performance.now() - t0 });
                    return;
                }
                requestAnimationFrame(step);
            }
            requestAnimationFrame(step);
            setTimeout(function () { resolve({ raf: n, raf_ms: performance.now() - t0 }); }, 1000);
        });
    }

    function privateHint() {
        try { localStorage.setItem('__hhub_p', '1'); localStorage.removeItem('__hhub_p'); }
        catch (e) { return true; }
        try { if (!window.indexedDB) return true; } catch (e) { return true; }
        return false;
    }

    function collectFp(t) {
        return {
            ua: navigator.userAgent,
            lang: (navigator.language || '').slice(0, 32),
            tz: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } })(),
            screen: screen.width + 'x' + screen.height + 'x' + (screen.colorDepth || 24),
            canvas: canvasHash(),
            webgl: webglInfo(),
            raf: t.raf,
            raf_ms: Math.round(t.raf_ms * 10) / 10,
            dpr: Math.round((window.devicePixelRatio || 1) * 100) / 100,
            private: privateHint()
        };
    }

    // ── PoW：材料与服务端逐字节一致 ──
    function powMaterial(challenge, mix, canvas, rafMs) {
        return challenge + '|' + mix + '|' + canvas + '|' + Math.round(rafMs * 10);
    }

    function solvePow(material, difficulty) {
        var zeros = '0'.repeat(Math.max(1, Math.min(6, difficulty | 0)));
        var i = 0, t0 = performance.now();
        return new Promise(function (resolve, reject) {
            function batch() {
                var end = i + 2000;
                for (; i < end; i++) {
                    if (sha256hex(material + i).indexOf(zeros) === 0) {
                        resolve({ nonce: String(i), attempts: i + 1, ms: Math.round(performance.now() - t0) });
                        return;
                    }
                    if (i > 500000) { reject(new Error('PoW 超时')); return; }
                }
                setTimeout(batch, 0);   // 让出主线程，避免页面卡顿
            }
            batch();
        });
    }

    function jsonFetch(url, body) {
        return fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            body: JSON.stringify(body)
        }).then(function (r) {
            return r.json().then(function (d) {
                if (!r.ok || !d || d.token === undefined && d.error) throw new Error(d.error || ('HTTP ' + r.status));
                return d;
            });
        });
    }

    var api = {
        init: function (opts) {
            cfg.endpoint = String((opts && opts.endpoint) || '').replace(/\/+$/, '');
            if (opts && opts.header) cfg.header = opts.header;
            if (cfg.inflight) return cfg.inflight;
            cfg.inflight = (async function () {
                var ch = await fetch(cfg.endpoint + '/v1/challenge', { method: 'POST', credentials: 'same-origin' })
                    .then(function (r) { return r.json(); });
                if (!ch || !ch.challenge) throw new Error('challenge 失败');
                var t = await rafTiming();
                var fp = collectFp(t);
                var pow = await solvePow(powMaterial(ch.challenge, ch.mix, fp.canvas, fp.raf_ms), ch.difficulty);
                var res = await jsonFetch(cfg.endpoint + '/v1/attest', {
                    challenge_id: ch.challenge_id, nonce: pow.nonce, fp: fp
                });
                cfg.token = res.token || '';
                cfg.last = { risk: res.risk, reasons: res.reasons || [], pow: pow, strong: !!res.strong };
                return cfg.token;
            })();
            cfg.inflight.catch(function () { cfg.inflight = null; });
            return cfg.inflight;
        },
        ready: function () { return cfg.inflight || Promise.resolve(cfg.token); },
        token: function () { return cfg.token; },
        last: function () { return cfg.last; },
        /** 业务请求：自动带上 token 头（没 token 时不带，由后端决定怎么处理）。 */
        fetch: function (input, init) {
            var opts = init ? Object.assign({}, init) : {};
            var headers = new Headers(opts.headers || {});
            if (cfg.token) headers.set(cfg.header, cfg.token);
            opts.headers = headers;
            return fetch(input, opts);
        },
        /** 行为遥测打分（服务端判定）。 */
        score: function (telemetry) {
            return jsonFetch(cfg.endpoint + '/v1/score', { telemetry: telemetry || {} });
        },
        __test: { sha256hex: sha256hex, powMaterial: powMaterial, collectFp: collectFp }
    };
    return api;
});

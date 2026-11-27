#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""多实例共享挑战 + 按 IP 限流的冒烟。

前置：
  RISK_REDIS=redis://127.0.0.1:6379/0 RISK_SECRET=test-secret RISK_LISTEN=127.0.0.1:8091 \
    cargo run -q -p hhub-risk-server &
  RISK_REDIS=redis://127.0.0.1:6379/0 RISK_SECRET=test-secret RISK_LISTEN=127.0.0.1:8093 \
    cargo run -q -p hhub-risk-server &

用法：python3 server/tests/multi_instance.py
"""
import hashlib
import json
import sys
import urllib.error
import urllib.request

A = "http://127.0.0.1:8091"
B = "http://127.0.0.1:8093"
FP = {
    "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "canvas": "c" * 64,
    "webgl": "Google|ANGLE",
    "raf": 20,
    "raf_ms": 333.0,
    "screen": "1920x1080x24",
    "tz": "Asia/Shanghai",
    "lang": "zh-CN",
}
passed = 0


def ok(cond, what):
    global passed
    if not cond:
        print("[FAIL]", what)
        sys.exit(1)
    passed += 1


def post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def solve(ch, mx, canvas, raf, d):
    material = f"{ch}|{mx}|{canvas}|{round(raf * 10)}"
    for i in range(2_000_000):
        if hashlib.sha256((material + str(i)).encode()).hexdigest().startswith("0" * d):
            return str(i)
    raise RuntimeError("no pow")


# 1) A 发挑战 → B 验（证明挑战存 Redis 而不是进程内存）
st, ch = post(A, "/v1/challenge", {})
ok(st == 200, "A 发挑战")
nonce = solve(ch["challenge"], ch["mix"], FP["canvas"], FP["raf_ms"], ch["difficulty"])
st, att = post(B, "/v1/attest", {"challenge_id": ch["challenge_id"], "nonce": nonce, "fp": FP})
ok(st == 200 and att.get("token"), f"B 能验证 A 发的挑战（Redis 共享；risk={att.get('risk')}）")

# 2) 同一挑战只能用一次
st, again = post(B, "/v1/attest", {"challenge_id": ch["challenge_id"], "nonce": nonce, "fp": FP})
ok(st == 400, "同一挑战第二次被拒（一次性）")

# 3) 限流：1 分钟内连续要 31 次挑战 → 必然出现 429
codes = [post(A, "/v1/challenge", {})[0] for _ in range(31)]
ok(429 in codes, "challenge 限流触发（30/min）")
ok(codes.count(200) <= 30, f"200 的次数不超过 30（实际 {codes.count(200)}）")

print(f"PASS={passed}")

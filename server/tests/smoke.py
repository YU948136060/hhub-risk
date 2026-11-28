#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""参考服务器的端到端冒烟：challenge → 绑定熵的 PoW → attest → token → score → verify。

用法：
  RISK_SECRET=test-secret cargo run -p hhub-risk-server &
  python3 server/tests/smoke.py
"""
import hashlib
import json
import math
import sys
import urllib.error
import urllib.request

import os
BASE = os.environ.get("RISK_BASE", "http://127.0.0.1:8090")
SECRET = os.environ.get("RISK_SECRET", "test-secret")
FP = {
    "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "canvas": "a" * 64,
    "webgl": "Google|ANGLE (test)",
    "raf": 20,
    "raf_ms": 333.0,
    "screen": "1920x1080x24",
    "tz": "Asia/Shanghai",
    "lang": "zh-CN",
}


def post(path, body):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return r.status, json.loads(r.read())


def solve(challenge, mix, canvas, raf_ms, d):
    material = f"{challenge}|{mix}|{canvas}|{round(raf_ms * 10)}"
    for i in range(2_000_000):
        if hashlib.sha256((material + str(i)).encode()).hexdigest().startswith("0" * d):
            return str(i)
    raise RuntimeError("找不到 PoW 解")


passed = 0


def ok(cond, what):
    global passed
    if not cond:
        print("[FAIL]", what)
        sys.exit(1)
    passed += 1


st, ch = post("/v1/challenge", {})
ok(st == 200 and "challenge_id" in ch, "challenge 可用")
nonce = solve(ch["challenge"], ch["mix"], FP["canvas"], FP["raf_ms"], ch["difficulty"])
st, att = post("/v1/attest", {"challenge_id": ch["challenge_id"], "nonce": nonce, "fp": FP})
ok(st == 200 and att.get("token"), f"attest 通过（strong={att.get('strong')}）")
token = att["token"]

# token 必须能被 SDK 本地验签（这里用 Python SDK 的实现验证协议一致）
sys.path.insert(0, "sdk/python")
from hhub_risk import verify  # noqa: E402

claims = verify(SECRET, token)
ok(claims is not None, "Python SDK 能验签服务器签出的 token")
ok(claims["fp"] == hashlib.sha256(
    "|".join([FP["canvas"], FP["webgl"], FP["screen"], FP["tz"], FP["lang"], ""]).encode()
).hexdigest()[:16], "fp 摘要一致")

st, sc = post("/v1/score", {"fp": FP, "telemetry": {"pointer": 12, "keys": 0, "corrections": 1,
                                                    "dwell_ms": 9000, "video_ms": 3000, "visible": True}})
st, sc2 = post("/v1/score", {"fp": FP, "telemetry": {}})
ok(st == 200 and sc["risk"] < sc2["risk"],
   f"人类遥测风险低于空遥测（{sc['risk']} < {sc2['risk']}）")
ok(sc["action"] in ("allow", "challenge"), f"人类遥测不会被直接拒绝（{sc['action']}）")
ok(sc2["action"] != "allow", f"空遥测不会放行（{sc2['action']}）")
st, v = get("/v1/verify?token=" + token)
ok(v.get("valid") is True, "verify 端点认可 token")
st, v2 = get("/v1/verify?token=" + token + "x")
ok(v2.get("valid") is False, "篡改 token 被拒")

# 换 canvas 复用同一份 PoW 必须失败（绑定熵）
st, ch2 = post("/v1/challenge", {})
st2, att2 = post("/v1/attest", {"challenge_id": ch2["challenge_id"], "nonce": nonce,
                                "fp": {**FP, "canvas": "b" * 64}})
ok(st2 == 400, "换指纹复用 PoW 被拒")
st, health = get("/healthz")
ok(health.get("ok") is True, "healthz")

# /metrics：参考实现也暴露最小 Prometheus 文本（TUI/CI 可抓）
with urllib.request.urlopen(BASE + "/metrics", timeout=10) as r:
    mt = r.read().decode()
ok("hhub_risk_challenges_total" in mt and "backend=" in mt, "metrics 端点")
ok("hhub_risk_attest_total{result=\"ok\"}" in mt, "metrics 含 attest 结果")
# /v1/stats：同一份数据的 JSON 版本（抓不了 Prometheus 的场景）
with urllib.request.urlopen(BASE + "/v1/stats", timeout=10) as r:
    stj = json.loads(r.read())
ok(stj["counters"]["challenges"] >= 2, "stats 含发题计数")
ok(stj["counters"]["attest_ok"] >= 1, "stats 含 attest 成功计数")
ok("attest_success_rate" in stj["rates"], "stats 含成功率")
ok(stj["store"] in ("memory", "redis"), "stats 含存储后端")
ok('hhub_risk_attest_rejected_total{reason=' in mt, "metrics 含拒因")
ok('hhub_risk_decision_total{action=' in mt, "metrics 含决策分布")

print(f"PASS={passed}")

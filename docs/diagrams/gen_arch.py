#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""生成 hhub-risk 架构图（英文 / 中文各一份 SVG）。

为什么用脚本而不是手写两份 SVG：
两份图的**结构必须完全一致**，只有文字不同；手写迟早漂移。
改动布局只改这里，然后 `python3 docs/diagrams/gen_arch.py`。

输出：
  docs/arch.svg      英文
  docs/arch.zh.svg   中文
"""
from __future__ import annotations

import os

W, H = 980, 560
BG = "#0d1117"
BOX = "#161b22"
LINE = "#30363d"
TEXT = "#e6edf3"
MUTED = "#9da7b3"
ACC = "#e8b93c"
GREEN = "#3fb950"
BLUE = "#58a6ff"
RED = "#f85149"

T = {
    "en": {
        "browser": "Browser (hhub-risk.js)",
        "l1": "L1  canvas / WebGL / rAF / UA",
        "l2": "L2  pointer / keys / dwell / video",
        "pow": "solve PoW bound to entropy",
        "server": "Risk server  (AGPL-3.0)",
        "verify": "verify PoW + environment evidence",
        "score": "score L1..L5  →  risk 0..100",
        "decide": "decide: allow / challenge / step_up / deny",
        "token": "sign HMAC token  (v1.<payload>.<sig>)",
        "app": "Your backend (SDK)",
        "sdk": "Go / Python / Node / Java / PHP",
        "act": "act on risk / action",
        "redis": "Redis: challenges · rate limits · optional history",
        "priv": "site-specific rules",
        "flow1": "POST /v1/challenge",
        "flow2": "POST /v1/attest\n(nonce + fingerprint)",
        "flow3": "X-HHub-Risk",
        "bound": "only generic layer is published · decisions are server-side",
        "nodeps": "zero dependencies · ~10 KB",
        "priv2": "not open source",
        "priv3": "Rule trait = interface only",
    },
    "zh": {
        "browser": "浏览器（hhub-risk.js）",
        "l1": "L1  canvas / WebGL / rAF / UA",
        "l2": "L2  指针 / 按键 / 停留 / 视频",
        "pow": "解绑定熵的 PoW",
        "server": "风控服务  （AGPL-3.0）",
        "verify": "校验 PoW + 环境证据",
        "score": "L1..L5 打分  →  risk 0..100",
        "decide": "决策：allow / challenge / step_up / deny",
        "token": "签发 HMAC token（v1.<载荷>.<签名>）",
        "app": "你的后端（SDK）",
        "sdk": "Go / Python / Node / Java / PHP",
        "act": "按 risk / action 处置",
        "redis": "Redis：挑战 · 限流 · 可选历史画像",
        "priv": "本站特有规则",
        "flow1": "POST /v1/challenge",
        "flow2": "POST /v1/attest\n（nonce + 指纹）",
        "flow3": "X-HHub-Risk",
        "bound": "只发布通用层 · 判定永远在服务端",
        "nodeps": "零依赖 · 约 10KB",
        "priv2": "不开源",
        "priv3": "只提供 Rule trait 接口",
    },
}

FONT = "-apple-system,'Noto Sans CJK SC','Microsoft YaHei',system-ui,sans-serif"


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def box(x, y, w, h, title, lines, accent=LINE, title_color=ACC, fill=BOX):
    out = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{accent}" stroke-width="1.5"/>',
        f'<text x="{x + 14}" y="{y + 27}" fill="{title_color}" font-size="16" font-weight="700">{esc(title)}</text>',
    ]
    for i, line in enumerate(lines):
        out.append(
            f'<text x="{x + 14}" y="{y + 52 + i * 21}" fill="{TEXT}" font-size="14">{esc(line)}</text>'
        )
    return "\n".join(out)


def arrow(x1, y1, x2, y2, label="", color=MUTED, dash=False):
    d = ' stroke-dasharray="5 4"' if dash else ""
    out = [
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.8" marker-end="url(#arrow)"{d}/>'
    ]
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        lines = label.split("\n")
        for i, line in enumerate(lines):
            # 多行标签整体上移，避免第二行压在箭头上
            y = my - 8 - (len(lines) - 1 - i) * 14
            out.append(
                f'<text x="{mx}" y="{y}" fill="{MUTED}" font-size="12" text-anchor="middle">{esc(line)}</text>'
            )
    return "\n".join(out)


def build(lang: str) -> str:
    t = T[lang]
    W, H = 1100, 470
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}"/></marker></defs>',
        f'<rect width="{W}" height="{H}" fill="{BG}"/>',
        f'<text x="28" y="40" fill="{ACC}" font-size="22" font-weight="700">hhub-risk</text>',
        f'<text x="170" y="40" fill="{MUTED}" font-size="13">{esc(t["bound"])}</text>',
        # 浏览器
        box(30, 72, 270, 156, t["browser"], [t["l1"], t["l2"], t["pow"], t["nodeps"]], accent=BLUE),
        # 风控服务（通用层）+ 内嵌"站点特有规则"虚线框
        box(440, 66, 310, 236, t["server"], [t["verify"], t["score"], t["decide"], t["token"]], accent=ACC),
        f'<rect x="452" y="200" width="286" height="90" rx="8" fill="#1b1214" stroke="{RED}" stroke-width="1.2" stroke-dasharray="6 4"/>',
        f'<text x="466" y="224" fill="{RED}" font-size="13" font-weight="700">{esc(t["priv"])}</text>',
        f'<text x="466" y="246" fill="{MUTED}" font-size="12">{esc(t["priv2"])}</text>',
        f'<text x="466" y="268" fill="{MUTED}" font-size="12">{esc(t["priv3"])}</text>',
        # 后端
        box(830, 72, 240, 156, t["app"], [t["sdk"], t["act"]], accent=GREEN),
        # Redis
        box(440, 350, 310, 66, "Redis", [t["redis"]], accent=LINE, title_color=MUTED),
        # 箭头
        arrow(302, 120, 438, 120, t["flow1"]),
        arrow(302, 188, 438, 188, t["flow2"]),
        arrow(752, 140, 828, 140, t["flow3"]),
        arrow(595, 304, 595, 348, "", LINE, dash=True),
        # 底部说明
        f'<text x="30" y="{H - 20}" fill="{MUTED}" font-size="12">'
        f'{esc("AGPL-3.0 (core/server) · Apache-2.0 (web/sdk) · one cross-language token vector")}</text>',
        "</svg>",
    ]
    return "\n".join(parts)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.abspath(os.path.join(here, ".."))
    for lang, name in (("en", "arch.svg"), ("zh", "arch.zh.svg")):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(build(lang))
        print("wrote", path)


if __name__ == "__main__":
    main()

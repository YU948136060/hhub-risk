#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""hhub-risk 文档站（HTTPS，127.0.0.1:8000）。

为什么自带一个 server 而不是 nginx：
- 这台机器没有 443，外部由 8888 端口转发到 `127.0.0.1:8000`；
- 只需要静态文件 + TLS，`http.server` 足够，不引入额外部署面。

用法：
  python3 risk/site/serve.py \
      --cert risk.hydrogen-ion.top.pem --key risk.hydrogen-ion.top.key \
      --root risk/site --bind 127.0.0.1 --port 8000
"""
from __future__ import annotations

import argparse
import http.server
import os
import ssl
import sys

# 文档站路由：`/` 首页；`/design.html`、`/quickstart.html` 由 build.sh 生成到 site/docs/
ROUTES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/design.html": "docs/design.html",
    "/quickstart.html": "docs/quickstart.html",
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    root = "."

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?")[0]
        rel = ROUTES.get(path)
        if rel is None and path.startswith("/static/"):
            rel = path.lstrip("/")
        if rel is None:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        full = os.path.normpath(os.path.join(self.root, rel))
        if not full.startswith(os.path.abspath(self.root)):
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".txt": "text/plain; charset=utf-8",
        }.get(os.path.splitext(full)[1], "application/octet-stream")
        self._send(200, body, ctype)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    a = ap.parse_args()

    Handler.root = a.root
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=a.cert, keyfile=a.key)

    httpd = http.server.ThreadingHTTPServer((a.bind, a.port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"risk docs: https://{a.bind}:{a.port}/  (root={a.root})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

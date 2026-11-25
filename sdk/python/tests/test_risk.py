# SPDX-License-Identifier: Apache-2.0
import json
import time
import unittest

from hhub_risk import Claims, ASGIMiddleware, verify

# 与 Rust core / Go SDK 共用的跨语言向量
VECTOR = ("v1.eyJhY3Rpb24iOiJjaGFsbGVuZ2UiLCJleHAiOjQxMDI0NDQ4MDAsImZwIjoiYWJjIiwicmlzayI6NDJ9."
          "Bg0XCR_JtF8muQbAt9td2o9WlNdxxs_8ZW9CtKIUF5o")
SECRET = "test-secret"


class TokenTest(unittest.TestCase):
    def test_rust_vector(self):
        c = verify(SECRET, VECTOR)
        self.assertIsNotNone(c)
        self.assertEqual(c.risk, 42)
        self.assertEqual(c.action, "challenge")
        self.assertEqual(c["fp"], "abc")

    def test_wrong_secret(self):
        self.assertIsNone(verify("other", VECTOR))

    def test_tampered(self):
        self.assertIsNone(verify(SECRET, VECTOR[:-2] + "aa"))
        self.assertIsNone(verify(SECRET, VECTOR + "x"))
        self.assertIsNone(verify(SECRET, "v2.aaa.bbb"))

    def test_expiry(self):
        c = verify(SECRET, VECTOR)
        self.assertTrue(c.valid(now=4102444799))
        self.assertFalse(c.valid(now=4102444800))

    def test_missing_header_is_worst_case(self):
        from hhub_risk import _claims_from_header
        c = _claims_from_header(None, SECRET)
        self.assertEqual(c.risk, 100)
        self.assertEqual(c.action, "deny")


class MiddlewareTest(unittest.IsolatedAsyncioTestCase):
    async def test_asgi_passes_and_injects(self):
        seen = {}

        async def app(scope, receive, send):
            seen.update(scope["state"]["risk"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = ASGIMiddleware(app, SECRET)
        sent = []

        async def send(msg):
            sent.append(msg)

        scope = {"type": "http", "headers": [(b"x-hhub-risk", VECTOR.encode())]}
        await mw(scope, None, send)
        self.assertEqual(seen["risk"], 42)
        self.assertEqual(sent[0]["status"], 200)

    async def test_asgi_denies(self):
        async def app(scope, receive, send):  # pragma: no cover - 不该被调用
            raise AssertionError("should not reach app")

        mw = ASGIMiddleware(app, SECRET, deny_at_or_above=40)
        sent = []

        async def send(msg):
            sent.append(msg)

        await mw({"type": "http", "headers": [(b"x-hhub-risk", VECTOR.encode())]}, None, send)
        self.assertEqual(sent[0]["status"], 403)
        body = json.loads(sent[1]["body"])
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()

// SPDX-License-Identifier: Apache-2.0
package top.hydrogenion.hhubrisk;


/** 零依赖测试入口：`java -cp out top.hydrogenion.hhubrisk.TestMain`。 */
public final class TestMain {
    // 与 Rust core / Go / Python / Node 共用的跨语言向量
    static final String VECTOR = "v1.eyJhY3Rpb24iOiJjaGFsbGVuZ2UiLCJleHAiOjQxMDI0NDQ4MDAsImZwIjoiYWJjIiwicmlzayI6NDJ9."
            + "Bg0XCR_JtF8muQbAt9td2o9WlNdxxs_8ZW9CtKIUF5o";
    static final String SECRET = "test-secret";

    private static int passed = 0;

    private static void ok(boolean cond, String what) {
        if (cond) { passed++; return; }
        System.err.println("[FAIL] " + what);
        System.exit(1);
    }

    public static void main(String[] args) {
        Claims c = HhubRisk.verify(SECRET, VECTOR);
        ok(c != null, "Rust 向量应验签通过");
        ok(c.risk() == 42, "risk=42");
        ok("challenge".equals(c.action()), "action=challenge");
        ok("abc".equals(c.fp()), "fp=abc");

        ok(HhubRisk.verify("other", VECTOR) == null, "换密钥必须失败");
        ok(HhubRisk.verify(SECRET, VECTOR.substring(0, VECTOR.length() - 2) + "aa") == null, "篡改必须失败");
        ok(HhubRisk.verify(SECRET, VECTOR + "x") == null, "多余段必须失败");
        ok(HhubRisk.verify(SECRET, "v2.a.b") == null, "版本不对必须失败");

        Claims d = HhubRisk.claimsOrDefault(SECRET, null);
        ok(d.risk() == 100, "缺 token 时 risk=100");
        ok("deny".equals(d.action()), "缺 token 时 action=deny");
        ok(d.reasons().contains("missing_or_bad_token"), "缺 token 时有 reason");

        ok(c.validAt(4102444799L), "过期前有效");
        ok(!c.validAt(4102444800L), "到点失效");

        System.out.println("PASS=" + passed);
    }
}

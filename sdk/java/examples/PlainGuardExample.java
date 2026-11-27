// SPDX-License-Identifier: Apache-2.0
package examples;

import top.hydrogenion.hhubrisk.Claims;
import top.hydrogenion.hhubrisk.HhubRisk;
import top.hydrogenion.hhubrisk.RiskGate;

/**
 * 无框架示例：任意 servlet / Spring / 网关里都适用。
 *
 * 用法：
 *   HHUB_RISK_SECRET=test-secret java -cp out examples.PlainGuardExample "<token>"
 *   没有 token 时打印 deny（fail-closed）。
 */
public final class PlainGuardExample {
    public static void main(String[] args) {
        String secret = System.getenv().getOrDefault("HHUB_RISK_SECRET", "test-secret");
        String header = args.length > 0 ? args[0] : "";
        Claims claims = HhubRisk.claimsOrDefault(secret, header);
        RiskGate gate = RiskGate.fromClaims(claims);
        System.out.println("{\"risk\":" + claims.risk()
                + ",\"gate\":\"" + gate.wireName()
                + "\",\"reasons\":" + claims.reasons() + "}");
        if (gate == RiskGate.DENY) {
            System.exit(2);
        }
    }
}

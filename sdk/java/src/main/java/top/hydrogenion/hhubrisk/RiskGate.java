// SPDX-License-Identifier: Apache-2.0
package top.hydrogenion.hhubrisk;

/** 把 risk 分数映射成业务动作。默认阈值与 Rust core 的 `decide()` 一致，可按站点覆盖。 */
public enum RiskGate {
    ALLOW, CHALLENGE, STEP_UP, DENY;

    /** 默认阈值：<30 allow、<70 challenge、<85 step_up、其余 deny。 */
    public static RiskGate fromClaims(Claims c) {
        return fromClaims(c, 30, 70, 85);
    }

    public static RiskGate fromClaims(Claims c, int allowBelow, int challengeBelow, int stepUpBelow) {
        return fromRisk(c.risk(), allowBelow, challengeBelow, stepUpBelow);
    }

    public static RiskGate fromRisk(int risk) {
        return fromRisk(risk, 30, 70, 85);
    }

    public static RiskGate fromRisk(int risk, int allowBelow, int challengeBelow, int stepUpBelow) {
        if (risk < allowBelow) return ALLOW;
        if (risk < challengeBelow) return CHALLENGE;
        if (risk < stepUpBelow) return STEP_UP;
        return DENY;
    }

    /** 小写名字，便于和 HTTP/JSON 对齐。 */
    public String wireName() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}

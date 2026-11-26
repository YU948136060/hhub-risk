// SPDX-License-Identifier: Apache-2.0
package top.hydrogenion.hhubrisk;

import java.util.List;
import java.util.Map;

/** 风控 token 的载荷。字段名与 Rust core / Go / Python / Node 一致。 */
public final class Claims {
    private final int risk;
    private final String action;
    private final String fp;
    private final long exp;
    private final List<String> reasons;

    Claims(int risk, String action, String fp, long exp, List<String> reasons) {
        this.risk = risk;
        this.action = action;
        this.fp = fp;
        this.exp = exp;
        this.reasons = reasons;
    }

    public int risk() { return risk; }
    public String action() { return action; }
    public String fp() { return fp; }
    public long exp() { return exp; }
    public List<String> reasons() { return reasons; }

    /** exp 为 0 视为不过期。 */
    public boolean validAt(long nowUnix) { return exp == 0 || nowUnix < exp; }

    static Claims from(Map<String, Object> m) {
        int risk = m.get("risk") instanceof Number n ? n.intValue() : 100;
        String action = m.get("action") instanceof String s ? s : "deny";
        String fp = m.get("fp") instanceof String s ? s : "";
        long exp = m.get("exp") instanceof Number n ? n.longValue() : 0L;
        List<String> reasons = HhubRisk.stringList(m.get("reasons"));
        return new Claims(risk, action, fp, exp, reasons);
    }

    @Override public String toString() {
        return "Claims{risk=" + risk + ", action=" + action + ", fp=" + fp + ", exp=" + exp
                + ", reasons=" + reasons + "}";
    }
}

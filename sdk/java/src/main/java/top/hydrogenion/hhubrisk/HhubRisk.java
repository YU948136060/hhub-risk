// SPDX-License-Identifier: Apache-2.0
package top.hydrogenion.hhubrisk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * hhub-risk 风控层 Java SDK（Apache-2.0）。
 *
 * <p>设计前提：**所有判定在服务端**。本 SDK 只做一件事：
 * 本地验签风控服务下发的 token（HMAC-SHA256），不需要回调。
 *
 * <p>token 格式与 Rust core / Go / Python / Node 完全一致：
 * <pre>v1.&lt;base64url(payload JSON)&gt;.&lt;base64url(HMAC-SHA256(secret, payload))&gt;</pre>
 *
 * <p>零运行时依赖：只用 JDK 自带的 {@link Mac} 与 {@link Base64}，JSON 用一个
 * 极小的解析器（只支持本 token 用到的类型：对象/字符串/数字/布尔/null/字符串数组）。
 */
public final class HhubRisk {
    public static final String HEADER = "X-HHub-Risk";

    private HhubRisk() {}

    /** 验签成功返回 Claims，失败返回 null（不区分"结构错"与"签名错"，避免探测）。 */
    public static Claims verify(String secret, String token) {
        if (secret == null || secret.isEmpty() || token == null || token.isEmpty()) return null;
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !"v1".equals(parts[0])) return null;
        byte[] body;
        byte[] sig;
        try {
            body = Base64.getUrlDecoder().decode(parts[1]);
            sig = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        byte[] want = hmacSha256(secret.getBytes(StandardCharsets.UTF_8), body);
        if (want == null || !MessageDigest.isEqual(sig, want)) return null;
        Map<String, Object> map = MiniJson.parseObject(new String(body, StandardCharsets.UTF_8));
        if (map == null) return null;
        return Claims.from(map);
    }

    /**
     * 中间件友好的入口：没有/无效 token 时返回"最坏情况"的 claims（risk=100, action=deny），
     * 但**不替业务做决定**。是否拒绝由调用方按 risk/action 判断。
     */
    public static Claims claimsOrDefault(String secret, String headerValue) {
        Claims c = verify(secret, headerValue);
        if (c != null) return c;
        return new Claims(100, "deny", "", 0L, List.of("missing_or_bad_token"));
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    static List<String> stringList(Object o) {
        if (o instanceof List<?> list) {
            List<String> out = new ArrayList<>(list.size());
            for (Object x : list) out.add(String.valueOf(x));
            return out;
        }
        return List.of();
    }

    /** 只覆盖 token 里可能出现的 JSON 子集；遇到不支持的形态返回 null，宁可不认。 */
    static final class MiniJson {
        private final String s;
        private int i;

        private MiniJson(String s) { this.s = s; }

        static Map<String, Object> parseObject(String text) {
            try {
                MiniJson p = new MiniJson(text);
                p.ws();
                if (p.peek() != '{') return null;
                Object v = p.value();
                p.ws();
                if (p.i != p.s.length()) return null;
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) v;
                return m;
            } catch (RuntimeException e) {
                return null;
            }
        }

        private char peek() { return s.charAt(i); }

        private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        private Object value() {
            ws();
            char c = peek();
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default: return number();
            }
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            ws();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws();
                String k = string();
                ws();
                if (s.charAt(i++) != ':') throw new IllegalStateException("colon");
                m.put(k, value());
                ws();
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw new IllegalStateException("comma");
            }
        }

        private List<Object> array() {
            List<Object> a = new ArrayList<>();
            i++; // [
            ws();
            if (peek() == ']') { i++; return a; }
            while (true) {
                a.add(value());
                ws();
                char c = s.charAt(i++);
                if (c == ']') return a;
                if (c != ',') throw new IllegalStateException("comma");
            }
        }

        private String string() {
            if (s.charAt(i++) != '"') throw new IllegalStateException("quote");
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c != '\\') { sb.append(c); continue; }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default: throw new IllegalStateException("escape");
                }
            }
        }

        private Object number() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            String t = s.substring(start, i);
            if (t.isEmpty()) throw new IllegalStateException("number");
            if (t.contains(".") || t.contains("e") || t.contains("E")) return Double.parseDouble(t);
            return Long.parseLong(t);
        }

        private void expect(String lit) {
            if (!s.startsWith(lit, i)) throw new IllegalStateException(lit);
            i += lit.length();
        }
    }
}

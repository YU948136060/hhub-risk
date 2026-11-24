//! hhub-risk-core —— 通用风控层（AGPL-3.0）。
//!
//! 设计边界（很重要）：
//!
//! * **这里只放通用信号与判定框架**：浏览器环境、行为遥测、网络/地理一致性、PoW 校验、token 签名。
//! * **不放任何具体站点的规则、阈值、特征**。站点特有逻辑通过 [`Rule`] 接口注入 ——
//!   开源部分只提供接口与场景启发，不提供实现。
//! * 本 crate **无 IO**（不碰 Redis/DB/网络）：调用方决定怎么存、怎么取。
//!   这样它既能嵌进 HHub 这种大服务，也能被一个 200 行的示例服务器直接用。
//!
//! 判定原则：客户端上报的一切都可以伪造，所以**只能当加分项**；拒绝/放行的决定永远在服务端，
//! 而且必须可解释（`reasons`），白箱用户才能自己调阈值。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 行为遥测（客户端采集）。
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Telemetry {
    /// 指针事件数（鼠标/触控笔/Pointer Events 的触摸）
    pub pointer: u32,
    /// 只发 touch* 事件的老移动浏览器点击数
    pub touch: u32,
    /// 键盘事件数（读屏/键盘用户）
    pub keys: u32,
    /// 视频 play 事件次数
    pub plays: u32,
    /// 改选次数（点错/犹豫）
    pub corrections: u32,
    /// 从发题到提交的毫秒数
    pub dwell_ms: u32,
    /// 视频播放到过的最大进度（毫秒）
    pub video_ms: u32,
    /// 页面是否可见
    pub visible: bool,
}

impl Telemetry {
    pub fn from_json(v: &serde_json::Value) -> Self {
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0).min(600_000) as u32;
        Telemetry {
            pointer: n("pointer"),
            touch: n("touch"),
            keys: n("keys"),
            plays: n("plays"),
            corrections: n("corrections"),
            dwell_ms: n("dwell_ms"),
            video_ms: n("video_ms"),
            visible: v.get("visible").and_then(|x| x.as_bool()).unwrap_or(true),
        }
    }
}

/// 低于这个分直接拒绝（不消耗验证码，用户可以立刻重试）。
pub const BLOCK_BELOW: u8 = 30;

/// 行为评分：0~100。返回 `(分数, 可解释标签)`。
///
/// 分项：指针/触摸 30、按键 15、停留 25、改选 10、视频 20、可见 5。
/// 刻意做松：键盘用户（0 指针）与只看视频的人也要能过。
pub fn score(telemetry: &Telemetry) -> (u8, &'static str) {
    let t = telemetry;
    let mut s: u32 = 0;
    let mut why = "robot";
    let act = t.pointer + t.touch;
    if act >= 3 {
        s += 30;
    } else if act >= 1 {
        s += 15;
    }
    if t.keys >= 1 {
        s += 15;
    }
    if t.dwell_ms >= 6_000 {
        s += 25;
    } else if t.dwell_ms >= 3_000 {
        s += 20;
    } else if t.dwell_ms >= 1_500 {
        s += 10;
    }
    if t.corrections >= 1 {
        s += 10;
    }
    if t.video_ms >= 1_500 || (t.plays >= 1 && t.video_ms >= 400) {
        s += 20;
    } else if t.video_ms >= 400 {
        s += 10;
    }
    if t.visible {
        s += 5;
    }
    if s >= 60 {
        why = "human-like";
    } else if s >= BLOCK_BELOW as u32 {
        why = "ok";
    }
    (s.min(100) as u8, why)
}

/// 决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    /// 要求验证码/PoW
    Challenge,
    /// 要求邮箱验证码等 step-up
    StepUp,
    Deny,
}

/// 站点特有规则的注入点。
///
/// 通用层只定义"怎么组合"，具体规则（社交平台的养号、刷屏、假互动等）由**调用方**实现，
/// 且不在本仓库里。`Rule::evaluate` 拿到的上下文是经过通用层整理的、已脱敏的字段。
pub trait Rule {
    /// 规则 id（写进 `reasons`，方便运营排查；白箱用户可据此关闭/调阈值）
    fn id(&self) -> &'static str;
    /// 返回 0..=100 的加分与可选说明
    fn evaluate(&self, ctx: &RiskContext) -> (u8, Option<String>);
}

/// 通用层整理出的上下文（站点规则只能看这些）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskContext {
    /// 声称的时区（IANA 名）
    pub tz: String,
    /// 声称的语言
    pub lang: String,
    /// IP 地理国家
    pub geo_country: String,
    /// IP 地理省/州
    pub geo_region: String,
    /// 指纹稳定 id（调用方计算，可脱敏）
    pub fp: String,
    /// 是否疑似无痕/隐私模式（客户端启发式，见 `private_suspected`）
    pub private: bool,
    /// 是否存在主设备会话
    pub has_primary_session: bool,
    /// 行为遥测
    pub telemetry: Telemetry,
}

/// 通用层打分：起点 50，行为分按比例折算，网络地理矛盾按规则加分。
///
/// 所有加分都带 `reasons`，不做"黑箱降权"。
pub fn evaluate(ctx: &RiskContext, rules: &[&dyn Rule]) -> (u8, Vec<String>) {
    let mut risk: i32 = 50;
    let mut reasons: Vec<String> = Vec::new();

    // 行为：满分人形 ≈ 减 20；空遥测 ≈ 加 15
    let (behavior, why) = score(&ctx.telemetry);
    risk += 15 - (behavior as i32) * 35 / 100;
    reasons.push(format!("behavior:{why}"));

    // 网络地理一致性（L3）
    if !ctx.tz.is_empty() && !ctx.geo_country.is_empty() {
        if let Some(diff) = tz_offset_diff_hours(&ctx.tz, &ctx.geo_country) {
            if diff >= 4 {
                risk += 12;
                reasons.push(format!("tz_geo_mismatch:{diff}h"));
            }
        }
    }
    if ctx.private && !ctx.has_primary_session {
        risk += 10;
        reasons.push("private_no_session".into());
    }

    for r in rules {
        let (add, note) = r.evaluate(ctx);
        if add > 0 {
            risk += add as i32;
            reasons.push(match note {
                Some(n) => format!("{}:{}", r.id(), n),
                None => r.id().to_string(),
            });
        }
    }
    (risk.clamp(0, 100) as u8, reasons)
}

/// 由分数映射决策。阈值集中在这里，方便白箱用户改。
pub fn decide(risk: u8) -> Action {
    if risk < 30 {
        Action::Allow
    } else if risk < 70 {
        Action::Challenge
    } else if risk < 85 {
        Action::StepUp
    } else {
        Action::Deny
    }
}

/// 时区与 IP 国家的大致偏移差（小时）。只做一个**粗**判断：用 tz 名映射到 UTC 偏移，
/// 国家只用于识别"明显不可能"的组合（例如 `Asia/Shanghai` + 美国）。
///
/// 这里刻意不内嵌完整 tz 数据库：只用常见的几组时区名做前缀匹配，未知时区返回 `None`
/// （宁可不加风险，也不误伤）。
fn tz_offset_diff_hours(tz: &str, country: &str) -> Option<u32> {
    let tz_off = tz_utc_offset(tz)?;
    let geo_off = country_utc_offset(country)?;
    Some(tz_off.abs_diff(geo_off))
}

fn tz_utc_offset(tz: &str) -> Option<i32> {
    // 只覆盖常见区域；其余返回 None（不判定）
    let t = tz.to_ascii_lowercase();
    if t.starts_with("asia/shanghai") || t.starts_with("asia/chongqing") || t.starts_with("asia/hong_kong")
        || t.starts_with("asia/taipei") || t.starts_with("asia/macau") || t.starts_with("asia/singapore")
    {
        return Some(8);
    }
    if t.starts_with("asia/tokyo") || t.starts_with("asia/seoul") { return Some(9); }
    if t.starts_with("asia/kolkata") { return Some(5); }
    if t.starts_with("asia/dubai") { return Some(4); }
    if t.starts_with("asia/bangkok") || t.starts_with("asia/jakarta") { return Some(7); }
    if t.starts_with("europe/london") { return Some(0); }
    if t.starts_with("europe/paris") || t.starts_with("europe/berlin") || t.starts_with("europe/rome")
        || t.starts_with("europe/madrid") || t.starts_with("europe/amsterdam") { return Some(1); }
    if t.starts_with("europe/moscow") { return Some(3); }
    if t.starts_with("america/new_york") || t.starts_with("america/toronto") { return Some(-5); }
    if t.starts_with("america/chicago") { return Some(-6); }
    if t.starts_with("america/denver") { return Some(-7); }
    if t.starts_with("america/los_angeles") || t.starts_with("america/vancouver") { return Some(-8); }
    if t.starts_with("australia/sydney") || t.starts_with("australia/melbourne") { return Some(10); }
    None
}

fn country_utc_offset(country: &str) -> Option<i32> {
    let c = country.to_ascii_lowercase();
    match c.as_str() {
        "china" | "hong kong" | "taiwan" | "singapore" | "macao" | "macau" => Some(8),
        "japan" | "south korea" | "korea" => Some(9),
        "india" => Some(5),
        "united arab emirates" => Some(4),
        "thailand" | "indonesia" | "vietnam" => Some(7),
        "united kingdom" => Some(0),
        "france" | "germany" | "italy" | "spain" | "netherlands" => Some(1),
        "russia" => Some(3),
        "united states" | "canada" => Some(-5),   // 只取东海岸作代表，误差由 |diff|≥4 的吸收
        "australia" => Some(10),
        _ => None,
    }
}

/// 签发 token：`v1.<b64url(payload)>.<b64url(hmac_sha256(payload))>`。
///
/// 调用方（任何语言的 SDK）都能**本地验签**，不需要回调 —— 这是"接入方便"的关键。
pub fn sign_token(secret: &[u8], payload: &serde_json::Value) -> String {
    let body = serde_json::to_vec(payload).unwrap_or_default();
    let sig = hmac_sha256(secret, &body);
    format!("v1.{}.{}", b64url(&body), b64url(&sig))
}

/// 验签并返回 payload。失败返回 None。
pub fn verify_token(secret: &[u8], token: &str) -> Option<serde_json::Value> {
    let mut it = token.split('.');
    if it.next()? != "v1" { return None; }
    let body = unb64url(it.next()?)?;
    let sig = unb64url(it.next()?)?;
    if it.next().is_some() { return None; }
    let want = hmac_sha256(secret, &body);
    if !constant_time_eq(&sig, &want) { return None; }
    serde_json::from_slice(&body).ok()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC-SHA256（不引额外依赖，按 RFC 2104 实现）
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finalize();
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut h = Sha256::new();
    h.update(ipad);
    h.update(data);
    let inner = h.finalize();
    let mut h2 = Sha256::new();
    h2.update(opad);
    h2.update(inner);
    h2.finalize().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut d = 0u8;
    for i in 0..a.len() { d |= a[i] ^ b[i]; }
    d == 0
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 { out.push(T[(n >> 6) as usize & 63] as char); }
        if chunk.len() > 2 { out.push(T[n as usize & 63] as char); }
    }
    out
}

fn unb64url(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(pointer: u32, keys: u32, corrections: u32, dwell: u32, video: u32) -> Telemetry {
        Telemetry { pointer, touch: 0, keys, plays: 0, corrections, dwell_ms: dwell, video_ms: video, visible: true }
    }

    #[test]
    fn bare_protocol_is_blocked() {
        let (s, why) = score(&Telemetry::default());
        assert!(s < BLOCK_BELOW);
        assert_eq!(why, "robot");
    }

    #[test]
    fn touch_only_user_passes() {
        let mut m = t(0, 0, 0, 4_000, 0);
        m.touch = 10;
        assert!(score(&m).0 >= BLOCK_BELOW);
    }

    #[test]
    fn typical_human_is_high() {
        assert!(score(&t(12, 0, 2, 9_000, 3_000)).0 >= 60);
    }

    #[test]
    fn tz_geo_mismatch_adds_risk() {
        let human = t(12, 0, 2, 9_000, 3_000);
        let base = RiskContext { tz: "Asia/Shanghai".into(), geo_country: "China".into(),
                                 telemetry: human, ..Default::default() };
        let mism = RiskContext { tz: "Asia/Shanghai".into(), geo_country: "United States".into(),
                                 telemetry: human, ..Default::default() };
        let (a, _) = evaluate(&base, &[]);
        let (b, reasons) = evaluate(&mism, &[]);
        assert!(b > a, "跨国时区不一致应当加分：{a} vs {b}");
        assert!(reasons.iter().any(|r| r.starts_with("tz_geo_mismatch")));
    }

    #[test]
    fn unknown_tz_is_not_penalized() {
        let human = t(12, 0, 2, 9_000, 3_000);
        let ctx = RiskContext { tz: "Mars/Olympus".into(), geo_country: "China".into(),
                                 telemetry: human, ..Default::default() };
        let (_, reasons) = evaluate(&ctx, &[]);
        assert!(!reasons.iter().any(|r| r.starts_with("tz_geo_mismatch")));
    }

    #[test]
    fn decision_thresholds() {
        assert_eq!(decide(0), Action::Allow);
        assert_eq!(decide(29), Action::Allow);
        assert_eq!(decide(30), Action::Challenge);
        assert_eq!(decide(69), Action::Challenge);
        assert_eq!(decide(70), Action::StepUp);
        assert_eq!(decide(85), Action::Deny);
    }

    #[test]
    fn token_roundtrip_and_tamper() {
        let secret = b"test-secret";
        let tok = sign_token(secret, &json!({"fp": "abc", "risk": 12, "exp": 123}));
        let got = verify_token(secret, &tok).expect("应能验签");
        assert_eq!(got["fp"], "abc");
        assert!(verify_token(b"other", &tok).is_none(), "换密钥必须失败");
        let mut bad = tok.clone();
        bad.push('x');
        assert!(verify_token(secret, &bad).is_none());
    }

    #[test]
    fn b64url_roundtrip() {
        for case in [&b""[..], b"a", b"ab", b"abc", &[0u8, 255, 1, 2][..]] {
            let e = b64url(case);
            assert_eq!(unb64url(&e).unwrap(), case.to_vec());
        }
    }
}

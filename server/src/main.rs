// SPDX-License-Identifier: AGPL-3.0-only
//! hhub-risk 参考服务器（**最小可跑**，故意只用 std + serde_json，不引 web 框架）。
//!
//! 目的不是生产部署，而是给 SDK/前端一个**能对齐协议**的参考实现：
//!
//! ```text
//! POST /v1/challenge   → {challenge_id, challenge, mix, difficulty}
//! POST /v1/attest      → 校验 PoW（绑定浏览器熵）+ 环境证据 → {token, ttl, risk, reasons}
//! POST /v1/score       → 行为遥测 + 上下文 → {risk, action, reasons}
//! GET  /v1/verify?token=… → {valid, claims}
//! GET  /healthz
//! ```
//!
//! 生产落地时请替换：
//! * 挑战存储（这里内存 + Mutex，多实例会失效 → 用 Redis）；
//! * IP 地理（这里只接受调用方传入的 `geo_country`）；
//! * TLS（这里明文 HTTP，前面必须挂反代）。
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const DIFFICULTY: u8 = 3;
const TOKEN_TTL_SECS: i64 = 1800;

mod redis_min;
mod store;

use store::Store;
type SharedStore = Arc<Store>;

/// 进程内计数器（`/metrics` 用）。参考实现不引 prometheus crate，
/// 输出就是最小可用的文本格式。
#[derive(Default)]
struct Counters {
    challenges: AtomicU64,
    attest_ok: AtomicU64,
    attest_bad: AtomicU64,
    score: AtomicU64,
    verify_ok: AtomicU64,
    verify_bad: AtomicU64,
    rate_limited_challenge: AtomicU64,
    rate_limited_attest: AtomicU64,
    /// attest 被拒原因：expired / non_browser / bad_pow / weak_evidence / other
    attest_rejected: [AtomicU64; 5],
    /// 决策分布：allow / challenge / step_up / deny
    decision: [AtomicU64; 4],
    /// 进程启动时间（Unix 秒），`/v1/stats` 的 uptime 用
    started_unix: AtomicU64,
}
type SharedCounters = Arc<Counters>;

impl Counters {
    fn new() -> Self {
        Counters {
            started_unix: AtomicU64::new(now_secs().max(0) as u64),
            ..Default::default()
        }
    }
}

/// `/v1/stats`：与 `/metrics` 同源，但给"抓不了 Prometheus"的场景一份 JSON。
///
/// ⚠️ 参考实现不鉴权；生产必须把它放到反代后面（或只绑回环），
/// 与 `/metrics` 一样按内部端点对待。
fn render_stats(c: &SharedCounters, store: &SharedStore) -> Value {
    let rej = |i: usize| c.attest_rejected[i].load(Ordering::Relaxed);
    let dec = |i: usize| c.decision[i].load(Ordering::Relaxed);
    let ok = c.attest_ok.load(Ordering::Relaxed);
    let failed = c.attest_bad.load(Ordering::Relaxed);
    let total = ok + failed;
    let rate = if total > 0 { (ok as f64) * 1000.0 / total as f64 } else { 0.0 };
    let uptime = (now_secs().max(0) as u64).saturating_sub(c.started_unix.load(Ordering::Relaxed));
    json!({
        "uptime_seconds": uptime,
        "store": store.backend(),
        "counters": {
            "challenges": c.challenges.load(Ordering::Relaxed),
            "attest_ok": ok,
            "attest_failed": failed,
            "attest_rejected": {
                "expired": rej(0), "non_browser": rej(1), "bad_pow": rej(2),
                "weak_evidence": rej(3), "other": rej(4),
            },
            "decision": {
                "allow": dec(0), "challenge": dec(1), "step_up": dec(2), "deny": dec(3),
            },
            "score": c.score.load(Ordering::Relaxed),
            "verify_ok": c.verify_ok.load(Ordering::Relaxed),
            "verify_failed": c.verify_bad.load(Ordering::Relaxed),
            "rate_limited": {
                "challenge": c.rate_limited_challenge.load(Ordering::Relaxed),
                "attest": c.rate_limited_attest.load(Ordering::Relaxed),
            },
        },
        "rates": {
            // 分母 = 通过 + 失败；只作参考（挑战过期也会计入失败）
            "attest_success_rate": (rate).round() / 10.0,
        },
    })
}

/// 判定原因归类（顺序必须与 `Counters::attest_rejected` 的下标一致）
fn reject_idx(status: &str, body: &Value) -> usize {
    if status == "200 OK" { return 5; }
    let e = body.get("error").and_then(Value::as_str).unwrap_or("");
    if e.contains("过期") || e.contains("已使用") { 0 }
    else if e.contains("浏览器") { 1 }
    else if e.contains("见证校验") { 2 }
    else if e.contains("环境信息") { 3 }
    else { 4 }
}

fn action_idx(action: &str) -> Option<usize> {
    match action {
        "allow" => Some(0),
        "challenge" => Some(1),
        "step_up" => Some(2),
        "deny" => Some(3),
        _ => None,
    }
}

fn render_metrics(c: &SharedCounters, store: &SharedStore) -> String {
    let backend = store.backend();
    let rej = |i: usize| c.attest_rejected[i].load(Ordering::Relaxed);
    let dec = |i: usize| c.decision[i].load(Ordering::Relaxed);
    format!(
        "# HELP hhub_risk_challenges_total 发出的挑战数（含被限流拒绝的）\n\
# TYPE hhub_risk_challenges_total counter\n\
hhub_risk_challenges_total {}\n\
# HELP hhub_risk_rate_limited_total 被按 IP 限流拒绝的次数（按端点）\n\
# TYPE hhub_risk_rate_limited_total counter\n\
hhub_risk_rate_limited_total{{endpoint=\"challenge\"}} {}\n\
hhub_risk_rate_limited_total{{endpoint=\"attest\"}} {}\n\
# HELP hhub_risk_attest_total 见证请求（按结果）\n\
# TYPE hhub_risk_attest_total counter\n\
hhub_risk_attest_total{{result=\"ok\"}} {}\n\
hhub_risk_attest_total{{result=\"failed\"}} {}\n\
# HELP hhub_risk_attest_rejected_total 见证被拒原因\n\
# TYPE hhub_risk_attest_rejected_total counter\n\
hhub_risk_attest_rejected_total{{reason=\"expired\"}} {}\n\
hhub_risk_attest_rejected_total{{reason=\"non_browser\"}} {}\n\
hhub_risk_attest_rejected_total{{reason=\"bad_pow\"}} {}\n\
hhub_risk_attest_rejected_total{{reason=\"weak_evidence\"}} {}\n\
hhub_risk_attest_rejected_total{{reason=\"other\"}} {}\n\
# HELP hhub_risk_decision_total 决策分布（attest/score 合计）\n\
# TYPE hhub_risk_decision_total counter\n\
hhub_risk_decision_total{{action=\"allow\"}} {}\n\
hhub_risk_decision_total{{action=\"challenge\"}} {}\n\
hhub_risk_decision_total{{action=\"step_up\"}} {}\n\
hhub_risk_decision_total{{action=\"deny\"}} {}\n\
# HELP hhub_risk_score_total 打分请求数\n\
# TYPE hhub_risk_score_total counter\n\
hhub_risk_score_total {}\n\
# HELP hhub_risk_verify_total token 验签请求数（按结果）\n\
# TYPE hhub_risk_verify_total counter\n\
hhub_risk_verify_total{{result=\"valid\"}} {}\n\
hhub_risk_verify_total{{result=\"invalid\"}} {}\n\
# HELP hhub_risk_store 挑战存储后端（1=当前）\n\
# TYPE hhub_risk_store gauge\n\
hhub_risk_store{{backend=\"{}\"}} 1\n",
        c.challenges.load(Ordering::Relaxed),
        c.rate_limited_challenge.load(Ordering::Relaxed),
        c.rate_limited_attest.load(Ordering::Relaxed),
        c.attest_ok.load(Ordering::Relaxed),
        c.attest_bad.load(Ordering::Relaxed),
        rej(0), rej(1), rej(2), rej(3), rej(4),
        dec(0), dec(1), dec(2), dec(3),
        c.score.load(Ordering::Relaxed),
        c.verify_ok.load(Ordering::Relaxed),
        c.verify_bad.load(Ordering::Relaxed),
        backend,
    )
}

fn random_hex(n: usize) -> String {
    use rand_like::Rng;
    let mut rng = Rng::new();
    (0..n).map(|_| format!("{:x}", rng.next() % 16)).collect()
}

/// 极小的线程无关 RNG：用系统时间 + 进程内计数混合 SHA-256。
/// 参考实现够用；生产请用 `getrandom`/`rand`（本站主仓库就是这么做的）。
mod rand_like {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct Rng {
        state: [u8; 32],
    }

    impl Rng {
        pub fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let mut h = Sha256::new();
            h.update(t.to_le_bytes());
            h.update(n.to_le_bytes());
            h.update(std::process::id().to_le_bytes());
            Rng { state: h.finalize().into() }
        }

        pub fn next(&mut self) -> u64 {
            let mut h = Sha256::new();
            h.update(self.state);
            self.state = h.finalize().into();
            u64::from_le_bytes(self.state[..8].try_into().unwrap_or([0; 8]))
        }
    }
}

/// `sha256(challenge | mix | canvas | round(raf_ms*10) | nonce)` 前缀 d 个 0。
fn verify_bound_pow(challenge: &str, mix: &str, canvas: &str, raf_ms: f64, nonce: &str, d: u8) -> bool {
    if challenge.is_empty() || mix.is_empty() || canvas.is_empty() || nonce.is_empty() || d == 0 || d > 6 {
        return false;
    }
    let material = format!("{challenge}|{mix}|{canvas}|{}", (raf_ms * 10.0).round() as i64);
    let mut h = Sha256::new();
    h.update(material.as_bytes());
    h.update(nonce.as_bytes());
    format!("{:x}", h.finalize()).starts_with(&"0".repeat(d as usize))
}

/// 环境证据计数：六项里至少 2 项才算"像浏览器"（与本站生产口径一致）。
fn fp_evidence(fp: &Value) -> (usize, bool) {
    let s = |k: &str| fp.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
    let canvas = s("canvas");
    let canvas_ok = canvas.len() >= 32 && canvas.chars().all(|c| c.is_ascii_hexdigit());
    let webgl = s("webgl");
    let webgl_ok = !webgl.is_empty() && webgl.len() <= 256;
    let raf = fp.get("raf").and_then(Value::as_u64).unwrap_or(0);
    let raf_ms = fp.get("raf_ms").and_then(Value::as_f64).unwrap_or(0.0);
    let raf_ok = raf >= 3 && (30.0..=30_000.0).contains(&raf_ms);
    let screen = s("screen");
    let screen_ok = screen.split('x').count() == 3 && screen.split('x').all(|p| p.parse::<u32>().is_ok());
    let tz_ok = !s("tz").is_empty();
    let lang_ok = !s("lang").is_empty();
    let n = [canvas_ok, webgl_ok, raf_ok, screen_ok, tz_ok, lang_ok].iter().filter(|x| **x).count();
    (n, n == 6)
}

fn fp_hash(fp: &Value) -> String {
    let mut h = Sha256::new();
    for k in ["canvas", "webgl", "screen", "tz", "lang"] {
        h.update(fp.get(k).and_then(Value::as_str).unwrap_or("").as_bytes());
        h.update(b"|");
    }
    let d = h.finalize();
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn http(mut s: TcpStream, peer: SocketAddr, store: SharedStore, secret: Vec<u8>, counters: SharedCounters) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        match s.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(p) = find_headers_end(&buf) { break p; }
                if buf.len() > 64 * 1024 { return; }
            }
            Err(_) => return,
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut it = req_line.split_whitespace();
    let method = it.next().unwrap_or("");
    let path = it.next().unwrap_or("");
    let mut content_len = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let body_start = header_end + 4;
    while buf.len() < body_start + content_len {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let body = String::from_utf8_lossy(&buf[body_start..(body_start + content_len).min(buf.len())]).to_string();

    let (status, payload) = route(method, path, &body, &peer, &store, &secret, &counters);
    let (ctype, text) = if path.split('?').next() == Some("/metrics") {
        ("text/plain; version=0.0.4; charset=utf-8", payload.as_str().unwrap_or("").to_string())
    } else {
        ("application/json; charset=utf-8", serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into()))
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = s.write_all(resp.as_bytes());
}

fn find_headers_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn route(method: &str, path: &str, body: &str, peer: &SocketAddr, store: &SharedStore, secret: &[u8], counters: &SharedCounters) -> (&'static str, Value) {
    let (path_only, query) = path.split_once('?').unwrap_or((path, ""));
    // 固定窗口限流：每分钟按 IP 计数（挑战 30、attest 20）
    let minute = now_secs() / 60;
    let ip = peer.ip().to_string();
    let (limit_path, limit) = match (method, path_only) {
        ("POST", "/v1/challenge") => ("challenge", 30i64),
        ("POST", "/v1/attest") => ("attest", 20i64),
        _ => ("", 0),
    };
    if limit > 0 {
        let key = format!("risk:rl:{limit_path}:{ip}:{minute}");
        if store.incr_rate(&key) > limit {
            match limit_path {
                "challenge" => counters.rate_limited_challenge.fetch_add(1, Ordering::Relaxed),
                _ => counters.rate_limited_attest.fetch_add(1, Ordering::Relaxed),
            };
            return ("429 Too Many Requests", json!({"error": "请求过于频繁，请稍后再试"}));
        }
    }
    match (method, path_only) {
        ("GET", "/healthz") => ("200 OK", json!({"ok": true})),
        ("GET", "/metrics") => ("200 OK", Value::String(render_metrics(counters, store))),
        ("GET", "/v1/stats") => ("200 OK", render_stats(counters, store)),
        ("POST", "/v1/challenge") => {
            counters.challenges.fetch_add(1, Ordering::Relaxed);
            ("200 OK", issue_challenge(store))
        }
        ("POST", "/v1/attest") => {
            let out = match parse_json(body) {
                Some(v) => attest(store, secret, &v),
                None => ("400 Bad Request", json!({"error": "body 必须是 JSON"})),
            };
            if out.0 == "200 OK" { counters.attest_ok.fetch_add(1, Ordering::Relaxed); }
            else {
                counters.attest_bad.fetch_add(1, Ordering::Relaxed);
                let idx = reject_idx(out.0, &out.1);
                if idx < 5 { counters.attest_rejected[idx].fetch_add(1, Ordering::Relaxed); }
            }
            if let Some(i) = out.1.get("action").and_then(Value::as_str).and_then(action_idx) {
                counters.decision[i].fetch_add(1, Ordering::Relaxed);
            }
            out
        }
        ("POST", "/v1/score") => {
            counters.score.fetch_add(1, Ordering::Relaxed);
            let out = match parse_json(body) {
                Some(v) => score(&v),
                None => ("400 Bad Request", json!({"error": "body 必须是 JSON"})),
            };
            if let Some(i) = out.1.get("action").and_then(Value::as_str).and_then(action_idx) {
                counters.decision[i].fetch_add(1, Ordering::Relaxed);
            }
            out
        }
        ("GET", "/v1/verify") => {
            let out = verify_token(query, secret);
            let valid = out.1.get("valid").and_then(Value::as_bool).unwrap_or(false);
            if valid { counters.verify_ok.fetch_add(1, Ordering::Relaxed); }
            else { counters.verify_bad.fetch_add(1, Ordering::Relaxed); }
            out
        }
        _ => ("404 Not Found", json!({"error": "not found"})),
    }
}

fn parse_json(s: &str) -> Option<Value> {
    serde_json::from_str(s).ok()
}

fn issue_challenge(store: &SharedStore) -> Value {
    let id = random_hex(16);
    let challenge = random_hex(16);
    let mix = random_hex(16);
    store.issue(&id, &challenge, &mix);
    json!({"challenge_id": id, "challenge": challenge, "mix": mix, "difficulty": DIFFICULTY})
}

fn attest(store: &SharedStore, secret: &[u8], body: &Value) -> (&'static str, Value) {
    let s = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
    let id = s("challenge_id");
    let nonce = s("nonce");
    let fp = body.get("fp").cloned().unwrap_or(Value::Null);
    if id.is_empty() || nonce.is_empty() || !fp.is_object() {
        return ("400 Bad Request", json!({"error": "缺少 challenge_id/nonce/fp"}));
    }
    let Some((challenge, mix)) = store.consume(&id) else {
        return ("400 Bad Request", json!({"error": "挑战已过期或已使用"}));
    };

    let ua = fp.get("ua").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    if ua.is_empty() || !ua.contains("mozilla/") || !(ua.contains("chrome") || ua.contains("safari") || ua.contains("firefox")) {
        return ("403 Forbidden", json!({"error": "客户端不是浏览器"}));
    }
    if ["curl", "wget", "python-requests", "go-http-client", "okhttp"].iter().any(|b| ua.contains(b)) {
        return ("403 Forbidden", json!({"error": "客户端不是浏览器"}));
    }
    let canvas = fp.get("canvas").and_then(Value::as_str).unwrap_or("");
    let raf_ms = fp.get("raf_ms").and_then(Value::as_f64).unwrap_or(0.0);
    if !verify_bound_pow(&challenge, &mix, canvas, raf_ms, &nonce, DIFFICULTY) {
        return ("400 Bad Request", json!({"error": "见证校验失败"}));
    }
    let (evidence, strong) = fp_evidence(&fp);
    if evidence < 2 {
        return ("403 Forbidden", json!({"error": "缺少浏览器环境信息"}));
    }

    let ctx = hhub_risk_core::RiskContext {
        tz: fp.get("tz").and_then(Value::as_str).unwrap_or("").to_string(),
        lang: fp.get("lang").and_then(Value::as_str).unwrap_or("").to_string(),
        geo_country: body.get("geo_country").and_then(Value::as_str).unwrap_or("").to_string(),
        private: fp.get("private").and_then(Value::as_bool).unwrap_or(false),
        telemetry: hhub_risk_core::Telemetry::default(),
        ..Default::default()
    };
    let (risk, reasons) = hhub_risk_core::evaluate(&ctx, &[]);
    let action = hhub_risk_core::decide(risk);
    let exp = now_secs() + TOKEN_TTL_SECS;
    let claims = json!({
        "risk": risk,
        "action": format!("{action:?}").to_lowercase(),
        "fp": fp_hash(&fp),
        "exp": exp,
        "reasons": reasons,
    });
    let token = hhub_risk_core::sign_token(secret, &claims);
    ("200 OK", json!({"token": token, "ttl": TOKEN_TTL_SECS, "risk": risk, "strong": strong, "reasons": claims["reasons"]}))
}

fn score(body: &Value) -> (&'static str, Value) {
    let fp = body.get("fp").cloned().unwrap_or(Value::Null);
    let telemetry = hhub_risk_core::Telemetry::from_json(body.get("telemetry").unwrap_or(&Value::Null));
    let ctx = hhub_risk_core::RiskContext {
        tz: fp.get("tz").and_then(Value::as_str).unwrap_or("").to_string(),
        lang: fp.get("lang").and_then(Value::as_str).unwrap_or("").to_string(),
        geo_country: body.get("geo_country").and_then(Value::as_str).unwrap_or("").to_string(),
        private: fp.get("private").and_then(Value::as_bool).unwrap_or(false),
        telemetry,
        ..Default::default()
    };
    let (risk, reasons) = hhub_risk_core::evaluate(&ctx, &[]);
    let action = hhub_risk_core::decide(risk);
    ("200 OK", json!({"risk": risk, "action": format!("{action:?}").to_lowercase(), "reasons": reasons}))
}

fn verify_token(query: &str, secret: &[u8]) -> (&'static str, Value) {
    let token = query.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "token")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    match hhub_risk_core::verify_token(secret, &token) {
        Some(claims) => ("200 OK", json!({"valid": true, "claims": claims})),
        None => ("200 OK", json!({"valid": false})),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn main() {
    let listen = std::env::var("RISK_LISTEN").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let secret = std::env::var("RISK_SECRET").unwrap_or_else(|_| {
        eprintln!("⚠️  RISK_SECRET 未设置，使用 dev-secret（生产必须改）");
        "dev-secret".into()
    });
    let store: SharedStore = Arc::new(Store::from_env());
    let counters: SharedCounters = Arc::new(Counters::new());
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("无法监听 {listen}: {e}");
            std::process::exit(1);
        }
    };
    println!("hhub-risk reference server on http://{listen}  (AGPL-3.0)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = match s.peer_addr() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let store = Arc::clone(&store);
                let counters = Arc::clone(&counters);
                let secret = secret.clone().into_bytes();
                std::thread::spawn(move || http(s, peer, store, secret, counters));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solve(challenge: &str, mix: &str, canvas: &str, raf: f64) -> String {
        for i in 0..200_000u32 {
            if verify_bound_pow(challenge, mix, canvas, raf, &i.to_string(), DIFFICULTY) {
                return i.to_string();
            }
        }
        panic!("找不到解");
    }

    #[test]
    fn pow_binds_to_fingerprint() {
        let (c, m, canvas) = ("c1", "m1", "a".repeat(64));
        let nonce = solve(c, m, &canvas, 333.3);
        assert!(verify_bound_pow(c, m, &canvas, 333.3, &nonce, DIFFICULTY));
        assert!(!verify_bound_pow(c, m, &"b".repeat(64), 333.3, &nonce, DIFFICULTY));
        assert!(!verify_bound_pow(c, m, &canvas, 400.0, &nonce, DIFFICULTY));
    }

    #[test]
    fn evidence_counting() {
        let fp = json!({"ua":"Mozilla/5.0 Chrome/131","canvas":"a".repeat(64),
                        "webgl":"Google|ANGLE","raf":20,"raf_ms":330.0,
                        "screen":"1920x1080x24","tz":"Asia/Shanghai","lang":"zh-CN"});
        assert_eq!(fp_evidence(&fp), (6, true));
        let bare = json!({"ua":"Mozilla/5.0 Chrome/131"});
        assert_eq!(fp_evidence(&bare).0, 0);
    }

    fn peer(ip: &str) -> SocketAddr {
        format!("{ip}:1234").parse().unwrap()
    }

    fn store() -> SharedStore { Arc::new(Store::memory()) }

    fn counters() -> SharedCounters { Arc::new(Counters::new()) }

    fn good_fp() -> Value {
        json!({"ua":"Mozilla/5.0 Chrome/131","canvas":"d".repeat(64),
               "webgl":"Google|ANGLE","raf":20,"raf_ms":333.0,
               "screen":"1920x1080x24","tz":"Asia/Shanghai","lang":"zh-CN"})
    }

    fn challenge(store: &SharedStore) -> Value {
        let (st, v) = route("POST", "/v1/challenge", "", &peer("127.0.0.9"), store, b"test-secret", &counters());
        assert_eq!(st, "200 OK");
        v
    }

    fn solve_v(ch: &Value, fp: &Value) -> String {
        solve(
            ch["challenge"].as_str().unwrap(),
            ch["mix"].as_str().unwrap(),
            fp["canvas"].as_str().unwrap(),
            fp["raf_ms"].as_f64().unwrap(),
        )
    }

    #[test]
    fn contract_challenge_attest_happy_path() {
        let st = store();
        let ch = challenge(&st);
        let fp = good_fp();
        let nonce = solve_v(&ch, &fp);
        let (status, out) = route("POST", "/v1/attest", &json!({
            "challenge_id": ch["challenge_id"], "nonce": nonce, "fp": fp,
        }).to_string(), &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(status, "200 OK", "{out}");
        assert!(out["token"].as_str().unwrap().starts_with("v1."));
        assert!(out["risk"].is_i64());
        // token 可被 verify 端点验签
        let token = out["token"].as_str().unwrap().to_string();
        let (_, v) = route("GET", &format!("/v1/verify?token={token}"), "", &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(v["valid"], true);
        let (_, bad) = route("GET", &format!("/v1/verify?token={token}x"), "", &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(bad["valid"], false);
    }

    #[test]
    fn contract_challenge_is_one_time() {
        let st = store();
        let ch = challenge(&st);
        let fp = good_fp();
        let nonce = solve_v(&ch, &fp);
        let body = json!({"challenge_id": ch["challenge_id"], "nonce": nonce, "fp": fp}).to_string();
        let (s1, _) = route("POST", "/v1/attest", &body, &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(s1, "200 OK");
        let (s2, _) = route("POST", "/v1/attest", &body, &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(s2, "400 Bad Request", "同一挑战必须只能用一次");
    }

    #[test]
    fn contract_rejects_bad_pow_and_non_browser() {
        let st = store();
        let ch = challenge(&st);
        let fp = good_fp();
        let (bad_pow, _) = route("POST", "/v1/attest", &json!({
            "challenge_id": ch["challenge_id"], "nonce": "0", "fp": fp,
        }).to_string(), &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(bad_pow, "400 Bad Request");

        let ch2 = challenge(&st);
        let mut curl = good_fp();
        curl["ua"] = json!("curl/8.5.0");
        let nonce = solve_v(&ch2, &curl);
        let (s, _) = route("POST", "/v1/attest", &json!({
            "challenge_id": ch2["challenge_id"], "nonce": nonce, "fp": curl,
        }).to_string(), &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(s, "403 Forbidden", "curl UA 应被拒");

        // 证据不足：ua 像浏览器，但只有 1 项环境（canvas），其余缺失
        let ch3 = challenge(&st);
        let sparse = json!({"ua":"Mozilla/5.0 Chrome/131","canvas":"e".repeat(64),
                            "raf":0,"raf_ms":0.0});
        let nonce3 = solve_v(&ch3, &sparse);
        let (s3, _) = route("POST", "/v1/attest", &json!({
            "challenge_id": ch3["challenge_id"], "nonce": nonce3, "fp": sparse,
        }).to_string(), &peer("127.0.0.9"), &st, b"test-secret", &counters());
        assert_eq!(s3, "403 Forbidden", "证据不足应被拒");
    }

    #[test]
    fn contract_score_and_rate_limit() {
        let st = store();
        let human = json!({"pointer":12,"keys":0,"corrections":1,"dwell_ms":9000,"video_ms":3000,"visible":true});
        let (_, a) = route("POST", "/v1/score", &json!({"fp": good_fp(), "telemetry": human}).to_string(),
                           &peer("127.0.0.8"), &st, b"test-secret", &counters());
        let (_, b) = route("POST", "/v1/score", &json!({"fp": good_fp(), "telemetry": {}}).to_string(),
                           &peer("127.0.0.8"), &st, b"test-secret", &counters());
        assert!(a["risk"].as_i64().unwrap() < b["risk"].as_i64().unwrap());
        assert_ne!(b["action"], "allow");

        // 同一个 IP 连续要 31 次挑战：第 31 次必须 429
        let mut codes = Vec::new();
        for _ in 0..31 {
            let (s, _) = route("POST", "/v1/challenge", "", &peer("127.0.0.7"), &st, b"test-secret", &counters());
            codes.push(s);
        }
        assert_eq!(codes.iter().filter(|s| **s == "200 OK").count(), 30);
        assert_eq!(codes.last().copied(), Some("429 Too Many Requests"));
    }

    #[test]
    fn stats_json_shape() {
        let store = Arc::new(Store::memory());
        let c: SharedCounters = Arc::new(Counters::new());
        c.challenges.fetch_add(3, Ordering::Relaxed);
        c.attest_ok.fetch_add(2, Ordering::Relaxed);
        c.attest_bad.fetch_add(1, Ordering::Relaxed);
        c.decision[1].fetch_add(2, Ordering::Relaxed);
        let v = render_stats(&c, &store);
        assert_eq!(v["store"], "memory");
        assert_eq!(v["counters"]["challenges"], 3);
        assert_eq!(v["counters"]["attest_ok"], 2);
        assert_eq!(v["counters"]["decision"]["challenge"], 2);
        // 2 / (2+1) = 66.7%
        assert_eq!(v["rates"]["attest_success_rate"], 66.7);
        assert!(v["uptime_seconds"].as_u64().is_some());
    }

    #[test]
    fn metrics_exposition() {
        let store = Arc::new(Store::memory());
        let c: SharedCounters = Arc::new(Counters::default());
        c.challenges.fetch_add(2, Ordering::Relaxed);
        c.attest_ok.fetch_add(1, Ordering::Relaxed);
        c.attest_rejected[1].fetch_add(3, Ordering::Relaxed);
        c.decision[2].fetch_add(1, Ordering::Relaxed);
        c.verify_bad.fetch_add(4, Ordering::Relaxed);
        c.rate_limited_attest.fetch_add(5, Ordering::Relaxed);
        let text = render_metrics(&c, &store);
        assert!(text.contains("hhub_risk_challenges_total 2"), "{text}");
        assert!(text.contains("hhub_risk_attest_total{result=\"ok\"} 1"), "{text}");
        assert!(text.contains("hhub_risk_attest_rejected_total{reason=\"non_browser\"} 3"), "{text}");
        assert!(text.contains("hhub_risk_decision_total{action=\"step_up\"} 1"), "{text}");
        assert!(text.contains("hhub_risk_verify_total{result=\"invalid\"} 4"), "{text}");
        assert!(text.contains("hhub_risk_rate_limited_total{endpoint=\"attest\"} 5"), "{text}");
        assert!(text.contains("backend=\"memory\""), "{text}");
    }

    #[test]
    fn fingerprint_hash_is_stable() {
        let fp = json!({"canvas":"x","webgl":"y","screen":"1x1x24","tz":"t","lang":"l"});
        assert_eq!(fp_hash(&fp).len(), 16);
        assert_eq!(fp_hash(&fp), fp_hash(&fp));
    }
}

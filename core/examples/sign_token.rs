// SPDX-License-Identifier: AGPL-3.0-only
//! 生成一份跨语言测试向量：同一条 payload + secret 的 token。
//! 用法：cargo run --example sign_token -- <secret> <json>
use serde_json::Value;

fn main() {
    let mut a = std::env::args().skip(1);
    let secret = a.next().unwrap_or_else(|| "test-secret".into());
    let payload = a.next().unwrap_or_else(|| {
        r#"{"risk":42,"action":"challenge","fp":"abc","exp":1767225600}"#.into()
    });
    let v: Value = serde_json::from_str(&payload).expect("payload 必须是 JSON");
    let tok = hhub_risk_core::sign_token(secret.as_bytes(), &v);
    println!("{tok}");
    assert!(hhub_risk_core::verify_token(secret.as_bytes(), &tok).is_some());
}

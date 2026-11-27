// SPDX-License-Identifier: AGPL-3.0-only
//! 挑战存储 + 限流计数。
//!
//! 两种后端：
//! * `Memory`：进程内（默认；单实例、测试、演示）；
//! * `Redis`：跨实例共享（`RISK_REDIS=redis://127.0.0.1:6379/0`）。
//!   多实例部署时**必须**用它，否则 A 实例发的挑战在 B 实例上不存在。
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::redis_min::{Redis, Resp};

pub const CHALLENGE_TTL: Duration = Duration::from_secs(120);

struct MemChallenge {
    challenge: String,
    mix: String,
    created: Instant,
}

pub enum Store {
    Memory { ch: Mutex<HashMap<String, MemChallenge>>, rl: Mutex<HashMap<String, (i64, Instant)>> },
    Redis(Redis),
}

impl Store {
    pub fn memory() -> Self {
        Store::Memory { ch: Mutex::new(HashMap::new()), rl: Mutex::new(HashMap::new()) }
    }

    pub fn from_env() -> Self {
        match std::env::var("RISK_REDIS") {
            Ok(url) if !url.trim().is_empty() => match Redis::parse(url.trim()) {
                Some(r) => {
                    // 起服时 ping 一下：连不上就明确报错，而不是运行时静默失败
                    match r.cmd(&["PING"]) {
                        Some(Resp::Str(s)) if s == "PONG" => {
                            println!("challenge store: Redis {url}");
                            Store::Redis(r)
                        }
                        other => {
                            eprintln!("RISK_REDIS 配置了但连不上（{other:?}），退回内存存储");
                            Store::memory()
                        }
                    }
                }
                None => {
                    eprintln!("RISK_REDIS 格式不对（要 redis://host:port/db），退回内存存储");
                    Store::memory()
                }
            },
            _ => {
                println!("challenge store: 内存（单实例；多实例请设 RISK_REDIS）");
                Store::memory()
            }
        }
    }

    pub fn issue(&self, id: &str, challenge: &str, mix: &str) {
        match self {
            Store::Memory { ch, .. } => {
                let mut m = ch.lock().unwrap_or_else(|e| e.into_inner());
                m.retain(|_, c| c.created.elapsed() < CHALLENGE_TTL);
                m.insert(id.to_string(), MemChallenge {
                    challenge: challenge.to_string(), mix: mix.to_string(), created: Instant::now(),
                });
            }
            Store::Redis(r) => {
                let payload = format!("{challenge}|{mix}");
                let _ = r.cmd(&["SETEX", &format!("risk:ch:{id}"), "120", &payload]);
            }
        }
    }

    /// 一次性取出并删除（`None` = 不存在/过期/已用过）。
    pub fn consume(&self, id: &str) -> Option<(String, String)> {
        match self {
            Store::Memory { ch, .. } => {
                let mut m = ch.lock().unwrap_or_else(|e| e.into_inner());
                let c = m.remove(id)?;
                if c.created.elapsed() >= CHALLENGE_TTL { return None; }
                Some((c.challenge, c.mix))
            }
            Store::Redis(r) => {
                let key = format!("risk:ch:{id}");
                let v = match r.cmd(&["GET", &key]) {
                    Some(Resp::Str(s)) => s,
                    _ => return None,
                };
                let _ = r.cmd(&["DEL", &key]);   // 一次性：取到就删（并发下最坏是两人都拿到，可接受）
                let (challenge, mix) = v.split_once('|')?;
                Some((challenge.to_string(), mix.to_string()))
            }
        }
    }

    /// 固定窗口计数：`(window_key)` 自增，返回新值。Redis 用 INCR+EXPIRE 70s；
    /// 内存用 (count, 窗口起点) 自己滚。
    pub fn incr_rate(&self, key: &str) -> i64 {
        match self {
            Store::Memory { rl, .. } => {
                let mut m = rl.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                m.retain(|_, (_, start)| now.duration_since(*start) < Duration::from_secs(90));
                let e = m.entry(key.to_string()).or_insert((0, now));
                e.0 += 1;
                e.0
            }
            Store::Redis(r) => {
                let n = match r.cmd(&["INCR", key]) {
                    Some(Resp::Int(n)) => n,
                    _ => return 0,
                };
                if n == 1 {
                    let _ = r.cmd(&["EXPIRE", key, "70"]);
                }
                n
            }
        }
    }
}

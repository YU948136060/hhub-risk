// SPDX-License-Identifier: AGPL-3.0-only
//! 极小的 Redis 客户端（RESP over std::net::TcpStream）。
//!
//! 为什么不用 `redis` crate：参考实现想保持"只有 std + serde_json"，
//! 而这里只需要 SETEX / GET / DEL / INCR / EXPIRE 五个命令。
//! 生产请换成熟的客户端（连接池、重连、超时策略都要复杂得多）。
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum Resp {
    Str(String),
    Int(i64),
    Nil,
    Err(String),
    Arr(Vec<Resp>),
}

pub struct Redis {
    addr: String,
    db: u32,
}

impl Redis {
    /// `redis://host:port/db`
    pub fn parse(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("redis://")?;
        let (addr, db) = match rest.split_once('/') {
            Some((a, d)) => (a.to_string(), d.parse::<u32>().ok()?),
            None => (rest.to_string(), 0),
        };
        if addr.is_empty() { return None; }
        Some(Redis { addr, db })
    }

    fn conn(&self) -> Option<TcpStream> {
        let s = TcpStream::connect(&self.addr).ok()?;
        s.set_read_timeout(Some(Duration::from_millis(800))).ok()?;
        s.set_write_timeout(Some(Duration::from_millis(800))).ok()?;
        let mut r = Redis { addr: self.addr.clone(), db: self.db };
        let _ = r.cmd_on(&s, &["SELECT", &self.db.to_string()])?;
        Some(s)
    }

    /// 每次调用新建连接（参考实现够用；生产用连接池）。
    pub fn cmd(&self, args: &[&str]) -> Option<Resp> {
        let s = self.conn()?;
        self.cmd_on(&s, args)
    }

    fn cmd_on(&self, s: &TcpStream, args: &[&str]) -> Option<Resp> {
        let mut w = s.try_clone().ok()?;
        let mut out = format!("*{}\r\n", args.len());
        for a in args {
            out.push_str(&format!("${}\r\n{}\r\n", a.len(), a));
        }
        w.write_all(out.as_bytes()).ok()?;
        let mut r = BufReader::new(s.try_clone().ok()?);
        read_reply(&mut r)
    }
}

fn read_line(r: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    let n = r.read_line(&mut line).ok()?;
    if n == 0 { return None; }
    Some(line.trim_end_matches(['\r', '\n']).to_string())
}

fn read_reply(r: &mut BufReader<TcpStream>) -> Option<Resp> {
    let line = read_line(r)?;
    let mut c = line.chars();
    let tag = c.next()?;
    let body = c.as_str().to_string();
    match tag {
        '+' => Some(Resp::Str(body)),
        '-' => Some(Resp::Err(body)),
        ':' => body.parse().ok().map(Resp::Int),
        '$' => {
            let n: i64 = body.parse().ok()?;
            if n < 0 { return Some(Resp::Nil); }
            let mut buf = vec![0u8; n as usize + 2];
            use std::io::Read;
            r.read_exact(&mut buf).ok()?;
            Some(Resp::Str(String::from_utf8_lossy(&buf[..n as usize]).to_string()))
        }
        '*' => {
            let n: i64 = body.parse().ok()?;
            if n < 0 { return Some(Resp::Nil); }
            let mut items = Vec::with_capacity(n as usize);
            for _ in 0..n { items.push(read_reply(r)?); }
            Some(Resp::Arr(items))
        }
        _ => None,
    }
}

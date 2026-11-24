# hhub-risk

> Self-hosted risk layer for social platforms: browser attestation + behaviour scoring +
> IP/geo consistency, with a pluggable captcha. **AGPL-3.0.**

## 为什么

自托管社交平台（Mastodon、Misskey、小型社区）经常只有两个选择：挂一个闭源验证码（用户数据出境），
或者什么都不做（被注册机淹没）。这个项目想做第三件事：

- 数据不出自己的服务器；
- 判定在**服务端**，客户端只采集（白箱也能有效）；
- 验证码**可插拔**（自带 ALTCHA / Cap / Turnstile 也行）；
- 接入成本按"几行代码"算，而不是"读三天文档"。

## 现状

| 层 | 内容 | 状态 |
|---|---|---|
| L1 浏览器见证 | canvas/WebGL/rAF/UA 一致性 + 绑定熵的 PoW | 已在 HHub 生产使用 |
| L2 行为评分 | 指针/触摸/按键/停留/改选/看视频 → 0~100 分 | 已在 HHub 生产使用 |
| L3 网络地理 | IP → 国家/省/市；时区/语言一致性 | 设计完成，开发中 |
| L4 长期画像 | 指纹/IP 日表、长期矛盾规则 | 未开始 |
| L5 账号/会话 | 新设备/无痕/主设备 | 未开始 |

## 仓库结构

```
risk/
  core/          Rust crate：信号打分、决策、token 签名（无 IO，可嵌进任何 Rust 服务）
  LICENSE        AGPL-3.0
```

后续：`server/`（参考 HTTP 服务）、`web/`（零依赖原生 JS + React/Vue/Svelte 薄壳）、
`sdk/{go,python,node,java,php}`。

## 边界

- **开源的是通用层**：验证码、PoW、浏览器见证、IP 地理、评分框架；
- **不开源的是本站特有的风控规则**（社交媒体场景的养号/刷屏/假互动等）。仓库里只会有
  **接口**与**场景启发清单**，不会包含任何站点的具体阈值与特征。

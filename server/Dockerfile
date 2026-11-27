# SPDX-License-Identifier: AGPL-3.0-only
# 构建上下文必须是仓库根（risk/），因为要同时拷 core 与 server。
FROM rust:1.83-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY server ./server
RUN cargo build --release -p hhub-risk-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 risk
COPY --from=build /src/target/release/hhub-risk-server /usr/local/bin/hhub-risk-server
USER risk
ENV RISK_LISTEN=0.0.0.0:8090
EXPOSE 8090
CMD ["hhub-risk-server"]

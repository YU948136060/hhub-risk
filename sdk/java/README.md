# hhub-risk-java

> hhub-risk 风控层 Java SDK（Apache-2.0）。**零运行时依赖**：只用 JDK 自带的
> `HmacSHA256` + `Base64`，自带一个极小的 JSON 解析器（只认 token 里出现的类型）。

## 安装

Maven（本地或等发布到 Maven Central 后）：

```xml
<dependency>
  <groupId>top.hydrogenion</groupId>
  <artifactId>hhub-risk</artifactId>
  <version>0.1.0</version>
</dependency>
```

## 接入（Spring Boot，三行）

```java
@Bean
FilterRegistrationBean<Filter> hhubRisk() {
    var reg = new FilterRegistrationBean<>(new Filter() {
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {
            var http = (HttpServletRequest) req;
            Claims c = HhubRisk.claimsOrDefault(secret, http.getHeader(HhubRisk.HEADER));
            http.setAttribute("risk", c);
            if (c.risk() >= 70) { ((HttpServletResponse) res).sendError(403); return; }
            chain.doFilter(req, res);
        }
    });
    reg.addUrlPatterns("/login", "/register");
    return reg;
}
```

业务里读：`Claims c = (Claims) request.getAttribute("risk");`

## 无框架示例（不依赖 servlet API）

`RiskGate` 把分数映射成 `allow / challenge / step_up / deny`，任意网关、gRPC filter、
自研 HTTP 层都能直接用：

```java
Claims c = HhubRisk.claimsOrDefault(secret, header);
switch (RiskGate.fromClaims(c)) {
    case ALLOW -> chain.doFilter(req, res);
    case DENY -> sendError(403);
    default -> sendChallenge(req, res);     // challenge / step_up
}
```

可运行示例：`examples/PlainGuardExample.java`（缺 token → `deny`，退出码 2）。

```bash
javac --release 17 -d out $(find src/main/java examples -name '*.java')
HHUB_RISK_SECRET=test-secret java -cp out examples.PlainGuardExample "<token>"
```

## 没有 servlet 容器的场景

SDK 本体只依赖 JDK：

```java
Claims c = HhubRisk.verify(secret, token);       // 失败返回 null
Claims d = HhubRisk.claimsOrDefault(secret, header); // 缺 token 时 risk=100
```

## 测试

无 JUnit 依赖，直接跑：

```bash
cd sdk/java
javac -encoding UTF-8 -d out $(find src/main/java src/test/java -name '*.java')
java -cp out top.hydrogenion.hhubrisk.TestMain   # PASS=13
```

测试向量与 Rust core / Go / Python / Node 共用，证明五种语言的验签实现一致。

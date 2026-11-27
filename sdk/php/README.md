# hhub-risk-php

> hhub-risk 风控层 PHP SDK（Apache-2.0）。零依赖：只用 PHP 自带的
> `hash_hmac` / `hash_equals` / `base64_decode`。

## 安装

```bash
composer require hhub-risk/hhub-risk
# 或直接把 src/ 拷进项目，require 一下
```

## 接入（PSR-15 框架：Slim / Laminas 等）

```php
$app->add(new \HHubRisk\Psr15Middleware($secret, 70)); // 70 分以上直接 403
```

业务里读：`$request->getAttribute('risk')`。

> PSR-15 中间件只有在装了 `psr/http-server-middleware` 时才会被定义；
> 没装时 `Psr15Middleware.php` 不声明任何类，避免强制依赖。

## 无框架示例

`examples/guard.php`：读 `X-HHub-Risk` → gate（allow/challenge/step_up/deny），
缺 token 时 **fail-closed 到 deny**（退出码 2）。

```bash
HHUB_RISK_SECRET=test-secret php sdk/php/examples/guard.php "<token>"
```

## 没有 PSR-15 的场景

```php
$claims = \HHubRisk\HhubRisk::claimsOrDefault($secret, $_SERVER['HTTP_X_HHUB_RISK'] ?? null);
if ((int)$claims['risk'] >= 70) { http_response_code(403); exit; }
```

## 测试

```bash
php sdk/php/tests/test.php     # PASS=12
```

测试向量与 Rust core / Go / Python / Node / Java 共用。

本机实测（PHP 8.5.4）：

```
$ php -l sdk/php/src/HhubRisk.php        # No syntax errors
$ php sdk/php/tests/test.php             # PASS=12
```

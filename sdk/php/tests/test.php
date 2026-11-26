<?php
// SPDX-License-Identifier: Apache-2.0
declare(strict_types=1);

require __DIR__ . '/../src/HhubRisk.php';

use HHubRisk\HhubRisk;

// 与 Rust core / Go / Python / Node / Java 共用的跨语言向量
const VECTOR = 'v1.eyJhY3Rpb24iOiJjaGFsbGVuZ2UiLCJleHAiOjQxMDI0NDQ4MDAsImZwIjoiYWJjIiwicmlzayI6NDJ9.'
    . 'Bg0XCR_JtF8muQbAt9td2o9WlNdxxs_8ZW9CtKIUF5o';
const SECRET = 'test-secret';

$passed = 0;
function ok(bool $cond, string $what): void {
    global $passed;
    if ($cond) { $passed++; return; }
    fwrite(STDERR, "[FAIL] $what\n");
    exit(1);
}

$c = HhubRisk::verify(SECRET, VECTOR);
ok($c !== null, 'Rust 向量应验签通过');
ok(($c['risk'] ?? null) === 42, 'risk=42');
ok(($c['action'] ?? null) === 'challenge', 'action=challenge');
ok(($c['fp'] ?? null) === 'abc', 'fp=abc');

ok(HhubRisk::verify('other', VECTOR) === null, '换密钥必须失败');
ok(HhubRisk::verify(SECRET, substr(VECTOR, 0, -2) . 'aa') === null, '篡改必须失败');
ok(HhubRisk::verify(SECRET, VECTOR . 'x') === null, '多余段必须失败');
ok(HhubRisk::verify(SECRET, 'v2.a.b') === null, '版本不对必须失败');

$d = HhubRisk::claimsOrDefault(SECRET, null);
ok(($d['risk'] ?? 0) === 100, '缺 token 时 risk=100');
ok(($d['action'] ?? '') === 'deny', '缺 token 时 action=deny');

ok(HhubRisk::valid($c, 4102444799) === true, '过期前有效');
ok(HhubRisk::valid($c, 4102444800) === false, '到点失效');

echo "PASS=$passed\n";

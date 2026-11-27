<?php
// SPDX-License-Identifier: Apache-2.0
declare(strict_types=1);
/**
 * 无框架示例：把 `X-HHub-Risk` 映射成 gate（allow/challenge/step_up/deny）。
 *
 * 用法：
 *   HHUB_RISK_SECRET=test-secret php sdk/php/examples/guard.php "<token>"
 *   缺 token 时默认 deny（fail-closed）。
 */
require __DIR__ . '/../src/HhubRisk.php';

$secret = getenv('HHUB_RISK_SECRET') ?: 'test-secret';
$header = $argv[1] ?? ($_SERVER['HTTP_X_HHUB_RISK'] ?? '');
$claims = \HHubRisk\HhubRisk::claimsOrDefault($secret, $header);
$risk = (int)($claims['risk'] ?? 100);

$gate = $risk < 30 ? 'allow'
      : ($risk < 70 ? 'challenge'
      : ($risk < 85 ? 'step_up' : 'deny'));

if ($gate === 'deny') {
    http_response_code(403);   // 必须在输出之前设置
}
echo json_encode([
    'risk' => $risk,
    'gate' => $gate,
    'reasons' => $claims['reasons'] ?? [],
], JSON_UNESCAPED_UNICODE), "\n";

if ($gate === 'deny') {
    exit(2);
}

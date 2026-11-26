<?php
// SPDX-License-Identifier: Apache-2.0
declare(strict_types=1);

namespace HHubRisk;

/**
 * hhub-risk 风控层 PHP SDK（Apache-2.0）。
 *
 * 设计前提：所有判定在服务端。本 SDK 只做一件事：**本地验签**
 * （HMAC-SHA256），不需要回调，也不依赖任何 Composer 包。
 *
 * token 格式与 Rust core / Go / Python / Node / Java 一致：
 *   v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256(secret, payload))>
 */
final class HhubRisk
{
    public const HEADER = 'X-HHub-Risk';

    /** 验签成功返回载荷数组，失败返回 null。 */
    public static function verify(string $secret, ?string $token): ?array
    {
        if ($secret === '' || $token === null || $token === '') {
            return null;
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] !== 'v1') {
            return null;
        }
        $body = self::b64urlDecode($parts[1]);
        $sig  = self::b64urlDecode($parts[2]);
        if ($body === null || $sig === null) {
            return null;
        }
        $want = hash_hmac('sha256', $body, $secret, true);
        if (!hash_equals($want, $sig)) {
            return null;
        }
        $data = json_decode($body, true);
        return is_array($data) ? $data : null;
    }

    /**
     * 没有/无效 token 时返回"最坏情况"（risk=100, action=deny），但**不替业务做决定**。
     */
    public static function claimsOrDefault(string $secret, ?string $headerValue): array
    {
        $c = self::verify($secret, $headerValue);
        if ($c !== null) {
            return $c;
        }
        return ['risk' => 100, 'action' => 'deny', 'reasons' => ['missing_or_bad_token']];
    }

    /** exp 为 0/缺省视为不过期。 */
    public static function valid(array $claims, ?int $now = null): bool
    {
        $exp = (int)($claims['exp'] ?? 0);
        if ($exp === 0) {
            return true;
        }
        return ($now ?? time()) < $exp;
    }

    private static function b64urlDecode(string $s): ?string
    {
        $pad = strlen($s) % 4;
        if ($pad > 0) {
            $s .= str_repeat('=', 4 - $pad);
        }
        $bin = base64_decode(strtr($s, '-_', '+/'), true);
        return $bin === false ? null : $bin;
    }
}

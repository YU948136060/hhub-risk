<?php
// SPDX-License-Identifier: Apache-2.0
declare(strict_types=1);

namespace HHubRisk;

/**
 * PSR-15 中间件（可选）。只有装了 psr/http-server-middleware 才会定义这个类，
 * 没装时整个文件不会声明任何东西 —— 与其它 SDK 的"零强制依赖"口径一致。
 *
 * 用法（Slim / Laminas 等）：
 *   $app->add(new \HHubRisk\Psr15Middleware($secret, 70));
 */
if (interface_exists('Psr\Http\Server\MiddlewareInterface')) {
    final class Psr15Middleware implements \Psr\Http\Server\MiddlewareInterface
    {
        public function __construct(
            private string $secret,
            private int $denyAtOrAbove = 0,
            private string $attribute = 'risk'
        ) {
        }

        public function process(
            \Psr\Http\Message\ServerRequestInterface $request,
            \Psr\Http\Server\RequestHandlerInterface $handler
        ): \Psr\Http\Message\ResponseInterface {
            $claims = HhubRisk::claimsOrDefault(
                $this->secret,
                $request->getHeaderLine(HhubRisk::HEADER)
            );
            $risk = (int)($claims['risk'] ?? 100);
            if ($this->denyAtOrAbove > 0 && $risk >= $this->denyAtOrAbove) {
                $json = json_encode([
                    'error' => '请求被风控拦截',
                    'risk' => $risk,
                    'action' => $claims['action'] ?? 'deny',
                    'reasons' => $claims['reasons'] ?? [],
                ], JSON_UNESCAPED_UNICODE);
                $resp = new \GuzzleHttp\Psr7\Response(403, ['Content-Type' => 'application/json; charset=utf-8'], $json);
                return $resp;
            }
            return $handler->handle($request->withAttribute($this->attribute, $claims));
        }
    }
}

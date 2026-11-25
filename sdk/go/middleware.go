// SPDX-License-Identifier: Apache-2.0
package hhubrisk

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Config 控制中间件行为。
//
// 默认策略是"缺 token 视为最高风险但不直接拒绝"：风控层不该让整站因为
// 一个配置错误就 500/403。需要硬拦就设 DenyOnMissing=true。
type Config struct {
	Secret []byte
	// Header 默认 "X-HHub-Risk"
	Header string
	// DenyOnMissing：没有 token 时直接 403（默认放行但 risk=100）
	DenyOnMissing bool
	// DenyAtOrAbove：risk 达到该值直接 403（0 = 不启用）
	DenyAtOrAbove int
	// Now 便于测试注入；nil 用 time.Now
	Now func() time.Time
}

type ctxKey struct{}

// FromContext 取中间件注入的 claims。ok=false 表示这次请求没有可用 token。
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// Middleware 返回一个包装后的 handler。
func Middleware(cfg Config) func(http.Handler) http.Handler {
	h := cfg.Header
	if h == "" {
		h = "X-HHub-Risk"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := r.Header.Get(h)
			claims := Claims{Risk: 100, Action: Deny, Reasons: []string{"missing_token"}}
			ok := false
			if tok != "" {
				c, err := Verify(cfg.Secret, tok)
				switch {
				case err == nil && c.Valid(now().Unix()):
					claims, ok = c, true
				case err == nil:
					claims.Reasons = []string{"expired"}
				default:
					claims.Reasons = []string{"bad_signature"}
				}
			}
			if !ok && cfg.DenyOnMissing {
				writeDeny(w, claims)
				return
			}
			if ok && cfg.DenyAtOrAbove > 0 && claims.Risk >= cfg.DenyAtOrAbove {
				writeDeny(w, claims)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, claims)
			w.Header().Set("X-HHub-Risk-Score", strconv.Itoa(claims.Risk))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeDeny(w http.ResponseWriter, c Claims) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-HHub-Risk-Score", strconv.Itoa(c.Risk))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   "请求被风控拦截",
		"risk":    c.Risk,
		"action":  c.Action,
		"reasons": c.Reasons,
	})
}

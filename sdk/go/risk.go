// SPDX-License-Identifier: Apache-2.0
//
// Package hhubrisk 是 hhub-risk 风控层的 Go SDK。
//
// 设计前提：**所有判定在服务端**。SDK 只做两件事：
//  1. 本地验签风控服务下发的 token（HMAC-SHA256，不需要回调）；
//  2. 把卷（risk/action/reasons）注入 context，交给业务决定放行还是加验证。
//
// token 格式（与 Rust core 完全一致）：
//
//	v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256(secret, payload JSON))>
package hhubrisk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Action 是服务端给出的处置建议。
type Action string

const (
	Allow     Action = "allow"
	Challenge Action = "challenge"
	StepUp    Action = "step_up"
	Deny      Action = "deny"
)

// Claims 是 token 的载荷。字段名与 Rust core / JS SDK 保持一致。
type Claims struct {
	Risk    int      `json:"risk"`
	Action  Action   `json:"action"`
	FP      string   `json:"fp,omitempty"`
	Exp     int64    `json:"exp,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	Version string   `json:"v,omitempty"`
}

var (
	ErrMalformed = errors.New("hhub-risk: token malformed")
	ErrSignature = errors.New("hhub-risk: bad signature")
)

// Verify 校验 token 并返回载荷。`secret` 必须与服务端一致。
func Verify(secret []byte, token string) (Claims, error) {
	var c Claims
	if len(secret) == 0 {
		return c, errors.New("hhub-risk: empty secret")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return c, ErrMalformed
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, ErrMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, ErrSignature
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, ErrMalformed
	}
	return c, nil
}

// Valid 是给业务用的便捷判断：签名通过且未过期。
func (c Claims) Valid(nowUnix int64) bool {
	return c.Exp == 0 || nowUnix < c.Exp
}

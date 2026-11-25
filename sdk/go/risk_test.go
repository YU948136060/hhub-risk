// SPDX-License-Identifier: Apache-2.0
package hhubrisk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 由 Rust core 的 examples/sign_token.rs 生成（跨语言一致性向量）：
//
//	secret  = "test-secret"
//	payload = {"risk":42,"action":"challenge","fp":"abc","exp":4102444800}
const vector = "v1.eyJhY3Rpb24iOiJjaGFsbGVuZ2UiLCJleHAiOjQxMDI0NDQ4MDAsImZwIjoiYWJjIiwicmlzayI6NDJ9.Bg0XCR_JtF8muQbAt9td2o9WlNdxxs_8ZW9CtKIUF5o"

func TestVerifyRustVector(t *testing.T) {
	c, err := Verify([]byte("test-secret"), vector)
	if err != nil {
		t.Fatalf("应验签通过: %v", err)
	}
	if c.Risk != 42 || c.Action != Challenge || c.FP != "abc" {
		t.Fatalf("载荷不对: %+v", c)
	}
	if _, err := Verify([]byte("other"), vector); err != ErrSignature {
		t.Fatalf("换密钥必须失败，得到 %v", err)
	}
	if _, err := Verify([]byte("test-secret"), vector+"x"); err == nil {
		t.Fatal("被篡改必须验签失败")
	}
}

func TestMiddlewareInjectsAndScores(t *testing.T) {
	var got Claims
	h := Middleware(Config{Secret: []byte("test-secret")})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, _ := FromContext(r.Context())
			got = c
			w.WriteHeader(200)
		}))
	req := httptest.NewRequest("GET", "/login", nil)
	req.Header.Set("X-HHub-Risk", vector)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || got.Risk != 42 {
		t.Fatalf("应放行并注入 claims: code=%d claims=%+v", rec.Code, got)
	}
	if rec.Header().Get("X-HHub-Risk-Score") != "42" {
		t.Fatalf("应回写分数头，得到 %q", rec.Header().Get("X-HHub-Risk-Score"))
	}
}

func TestMiddlewareDenies(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("不该到达 next") })

	// 缺 token + DenyOnMissing
	rec := httptest.NewRecorder()
	Middleware(Config{Secret: []byte("s"), DenyOnMissing: true})(next).
		ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 403 {
		t.Fatalf("缺 token 应 403，得到 %d", rec.Code)
	}

	// 分数阈值
	rec2 := httptest.NewRecorder()
	Middleware(Config{Secret: []byte("test-secret"), DenyAtOrAbove: 40})(next).
		ServeHTTP(rec2, requestWithToken(vector))
	if rec2.Code != 403 {
		t.Fatalf("risk=42 ≥ 40 应 403，得到 %d", rec2.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &body); err != nil || body["error"] == nil {
		t.Fatalf("拒绝时应返回 JSON 错误：%s", rec2.Body.String())
	}
}

func TestExpiry(t *testing.T) {
	c, _ := Verify([]byte("test-secret"), vector)
	// vector 的 exp=4102444800（2100-01-01）
	if !c.Valid(time.Unix(4102444799, 0).Unix()) {
		t.Fatal("过期前应有效")
	}
	if c.Valid(time.Unix(4102444800, 0).Unix()) {
		t.Fatal("到点即失效")
	}
}

func requestWithToken(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/x", nil)
	r.Header.Set("X-HHub-Risk", tok)
	return r
}

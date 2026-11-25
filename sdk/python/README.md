# hhub-risk-python

> hhub-risk 风控层 Python SDK（Apache-2.0）。本地验签 + ASGI/WSGI 中间件。

## 安装

```bash
pip install -e sdk/python      # 目前仓库内可直接用
```

## 接入（FastAPI / Starlette）

```python
from hhub_risk import ASGIMiddleware

app.add_middleware(ASGIMiddleware, secret=os.environ["RISK_SECRET"], deny_at_or_above=70)
```

业务里读分数：

```python
@app.get("/login")
def login(request: Request):
    risk = request.state.risk            # Claims(dict)
    if risk.risk >= 30:
        ...                              # 要求人机验证
```

## 接入（Flask / Django WSGI）

```python
from hhub_risk import WSGIMiddleware
app.wsgi_app = WSGIMiddleware(app.wsgi_app, secret=secret, deny_at_or_above=70)
```

## 跨语言一致性

token 格式与 Rust core / Go / Node 完全一致；本地测试用的固定向量由
`cargo run --example sign_token -- test-secret '<json>'` 生成。

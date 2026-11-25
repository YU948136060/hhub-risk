# 部署说明（文档站）

本机没有 443：外网 `risk.hydrogen-ion.top:8888` → 本机 nginx `listen 8888` → 静态目录
`/home/heavenly-hound/HHub/risk/site`。

```bash
# 1) 证书（用户已下载到仓库根目录）
sudo cp risk.hydrogen-ion.top.pem risk.hydrogen-ion.top.key /etc/ssl/hhub/

# 2) nginx 站点
sudo cp risk/deploy/nginx-risk.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx

# 3) 验证
curl -I https://risk.hydrogen-ion.top:8888/
```

没有 sudo 时的临时入口（已可用）：
`https://hydrogen-ion.top:8888/static/risk/index.html`

独立 TLS 预览（不依赖 nginx）：

```bash
python3 risk/site/serve.py --port 8001 \
  --cert risk.hydrogen-ion.top.pem --key risk.hydrogen-ion.top.key
```

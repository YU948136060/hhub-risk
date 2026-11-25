#!/bin/sh
# 把 docs/*.md 渲染成 site/*.html（用 pandoc，带统一模板）
set -e
cd "$(dirname "$0")"
for f in ../docs/*.md; do
  name=$(basename "$f" .md)
  pandoc "$f" -f gfm -t html5 --standalone \
    --metadata title="hhub-risk · $name" \
    --metadata lang=zh-CN \
    --css ../style.css \
    --include-in-header=/dev/null \
    -o "docs/$name.html"
done
# 修正 pandoc 的 <header> 标题，让站点头部一致
for f in docs/*.html; do
  python3 - "$f" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
s = s.replace('<header id="title-block-header">', '<header id="title-block-header" class="doc-title">')
nav = ('<nav style="max-width:860px;margin:0 auto;padding:16px 24px">'
       '<a href="../index.html" style="color:#e8b93c;text-decoration:none;font-weight:700">hhub-risk</a>'
       ' <span style="color:#9da7b3;font-size:13px">/ 文档</span></nav>')
s = s.replace('<body>', '<body>' + nav, 1)
open(p, 'w', encoding='utf-8').write(s)
PY
done
echo "built: $(ls docs/*.html | wc -l) pages"

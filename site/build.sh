#!/bin/sh
# 把 docs/*.md 渲染成双语静态站：
#   /            → English
#   /zh/         → 中文
# 用法：./build.sh（在 site/ 目录运行；需要 pandoc）
set -e
cd "$(dirname "$0")"
mkdir -p docs zh zh/docs

render() { # $1=md 文件  $2=输出文件  $3=css 相对路径  $4=语言  $5=切语言链接
  pandoc "$1" -f gfm -t html5 --standalone \
    --metadata title="hhub-risk · $(basename "$1" .md)" \
    --metadata lang="$4" \
    --css "$3" \
    -o "$2"
  python3 - "$2" "$4" "$5" <<'PY'
import sys
path, lang, alt = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding='utf-8').read()
if lang == 'en':
    nav = ('<nav style="max-width:860px;margin:0 auto;padding:16px 24px;font:14px system-ui">'
           '<a href="/" style="color:#e8b93c;text-decoration:none;font-weight:700">hhub-risk</a> '
           '<span style="color:#9da7b3">/ docs</span>'
           f'<span style="float:right"><a href="{alt}" style="color:#9da7b3">中文</a></span></nav>')
else:
    nav = ('<nav style="max-width:860px;margin:0 auto;padding:16px 24px;font:14px system-ui">'
           '<a href="/zh/" style="color:#e8b93c;text-decoration:none;font-weight:700">hhub-risk</a> '
           '<span style="color:#9da7b3">/ 文档</span>'
           f'<span style="float:right"><a href="{alt}" style="color:#9da7b3">English</a></span></nav>')
s = s.replace('<body>', '<body>' + nav, 1)
open(path, 'w', encoding='utf-8').write(s)
PY
}

# English（默认）
render ../docs/design.md docs/design.html "../style.css" en "/zh/docs/design.html"
render ../docs/quickstart.md docs/quickstart.html "../style.css" en "/zh/docs/quickstart.html"
# 中文
render ../docs/design.zh-CN.md zh/docs/design.html "../../style.css" zh "/docs/design.html"
render ../docs/quickstart.zh-CN.md zh/docs/quickstart.html "../../style.css" zh "/docs/quickstart.html"

echo "built: $(ls docs/*.html zh/docs/*.html | wc -l) pages"

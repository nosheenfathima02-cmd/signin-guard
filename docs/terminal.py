"""Render a captured command output as a terminal-style HTML page (used for README screenshots)."""
import html
import sys

title, command, src, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
body = html.escape(open(src).read().rstrip())
for word, color in (("[CRITICAL]", "#ff6b6b"), ("[HIGH    ]", "#ffa94d"), ("... ok", "#69db7c"), ("OK", "#69db7c")):
    body = body.replace(html.escape(word), f'<span style="color:{color};font-weight:700">{html.escape(word)}</span>')
page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#e9ecf1;padding:28px;font-family:system-ui,sans-serif}}
.win{{background:#141a23;border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.25);display:inline-block;min-width:900px}}
.bar{{background:#232b37;padding:10px 14px;display:flex;gap:8px;align-items:center;color:#9aa6b8;font-size:13px}}
.dot{{width:12px;height:12px;border-radius:50%}}
pre{{margin:0;padding:18px 20px 22px;color:#dbe4ef;font:14px/1.55 "DejaVu Sans Mono",Menlo,Consolas,monospace;white-space:pre}}
.cmd{{color:#74c0fc}}
</style></head><body><div class="win"><div class="bar"><span class="dot" style="background:#ff5f57"></span>
<span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>&nbsp; {html.escape(title)}</div>
<pre><span class="cmd">$ {html.escape(command)}</span>
{body}</pre></div></body></html>"""
open(out, "w").write(page)

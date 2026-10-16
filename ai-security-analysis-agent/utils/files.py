def numbered_html(code: str, error_line: int | None = None, max_lines: int = 400) -> str:
    """HTML code view with line numbers; the error line is highlighted in red."""
    import html
    rows = []
    for i, ln in enumerate(code.splitlines()[:max_lines], 1):
        bad = (i == error_line)
        bg = "background:#7f1d1d;" if bad else ""
        mark = "&#9888; " if bad else ""
        rows.append(f'<div style="{bg}white-space:pre;font-family:Consolas,monospace;font-size:13px;">'
                    f'<span style="color:#9ca3af;display:inline-block;width:3em;text-align:right;margin-right:1em;">{i}</span>'
                    f'{mark}{html.escape(ln)}</div>')
    return '<div style="background:#111827;padding:10px;border-radius:6px;overflow-x:auto;max-height:420px;overflow-y:auto;">' + "".join(rows) + "</div>"


def soften(text: str, limit: int = 700) -> str:
    """Turn markdown headings into bold lines so guidance excerpts display compactly."""
    import re
    t = re.sub(r"^\s*#{1,6}\s*(.+)$", r"**\1**", text, flags=re.M)
    return t[:limit] + ("..." if len(t) > limit else "")

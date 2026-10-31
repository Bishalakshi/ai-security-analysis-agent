SEV_BG = {"CRITICAL": "#7f1d1d", "HIGH": "#9a3412", "MEDIUM": "#854d0e", "LOW": "#1e3a8a", "INFORMATIONAL": "#374151"}


def numbered_html(code: str, error_line: int | None = None, max_lines: int = 400, flags: dict | None = None) -> str:
    """HTML code view with line numbers. The syntax-error line is red; `flags` maps line -> (severity, label)
    for lines flagged by the analysis agents."""
    import html
    flags = flags or {}
    rows = []
    for i, ln in enumerate(code.splitlines()[:max_lines], 1):
        bad = (i == error_line)
        sev, label = flags.get(i, (None, ""))
        bg = "background:#7f1d1d;" if bad else (f"background:{SEV_BG[sev]};" if sev else "")
        mark = "&#9888; " if bad else ("&#9873; " if sev else "")
        tip = f' title="{html.escape(label)}"' if label else ""
        rows.append(f'<div{tip} style="{bg}white-space:pre;font-family:Consolas,monospace;font-size:13px;">'
                    f'<span style="color:#9ca3af;display:inline-block;width:3em;text-align:right;margin-right:1em;">{i}</span>'
                    f'{mark}{html.escape(ln)}</div>')
    return '<div style="background:#111827;padding:10px;border-radius:6px;overflow-x:auto;max-height:420px;overflow-y:auto;">' + "".join(rows) + "</div>"


def soften(text: str, limit: int = 700) -> str:
    """Turn markdown headings into bold lines so guidance excerpts display compactly."""
    import re
    t = re.sub(r"^\s*#{1,6}\s*(.+)$", r"**\1**", text, flags=re.M)
    return t[:limit] + ("..." if len(t) > limit else "")

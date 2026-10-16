"""Heading-aware chunking: split on paragraphs, keep the section heading in every chunk."""
import re


def split_text(text: str, size: int = 900, overlap: int = 120):
    heading, paras, chunks, buf = "", re.split(r"\n\s*\n", text), [], ""
    for p in paras:
        p = p.strip()
        if not p:
            continue
        if p.startswith("#"):
            heading = p.split("\n")[0].lstrip("# ").strip()
        if len(buf) + len(p) + 2 > size and buf:
            chunks.append(buf.strip())
            tail = buf[-overlap:] if overlap else ""
            tail = tail[tail.find(" ") + 1:] if " " in tail else tail   # start on a word boundary
            buf = (f"[{heading}] " if heading and not p.startswith("#") else "") + tail + "\n\n"
        while len(p) > size:                      # very long paragraph / code block
            chunks.append((buf + p[:size]).strip()); p = p[size - overlap:]; buf = ""
        buf += p + "\n\n"
    if buf.strip():
        chunks.append(buf.strip())
    return [c for c in chunks if len(c) > 40]


def split_documents(docs, size: int = 900, overlap: int = 120):
    out = []
    for d in docs:
        for i, c in enumerate(split_text(d["text"], size, overlap)):
            out.append({**{k: v for k, v in d.items() if k != "text"}, "text": c, "chunk_id": f'{d["source"]}#{i}'})
    return out

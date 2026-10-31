"""Load markdown / text knowledge-base files and read their front-matter metadata."""
import os
import re

FM = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)


def parse_front_matter(text: str):
    m = FM.match(text)
    meta = {}
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip().strip('"')
        text = text[m.end():]
    return meta, text


def load_documents(kb_dir: str):
    docs = []
    for root, _, files in os.walk(kb_dir):
        for f in sorted(files):
            if f.lower().endswith((".md", ".txt")) and f.lower() != "sources.md":
                path = os.path.join(root, f)
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    meta, body = parse_front_matter(fh.read())
                docs.append({"source": os.path.relpath(path, kb_dir).replace("\\", "/"), "text": body,
                             "title": meta.get("title", f), "category": meta.get("category", "general"),
                             "language": meta.get("language", "general"), "url": meta.get("source_url", ""),
                             "license": meta.get("license", "")})
    return docs

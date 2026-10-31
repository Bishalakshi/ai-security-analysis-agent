"""AI Code Review & Security Analysis Agent - Milestone 2 dashboard.
Run from the project root:  streamlit run ui/app.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import json

import streamlit as st
from agents import review
from agents.orchestrator import AGENT_LABEL
from models.findings import SEVERITY_ORDER
from parsers.validate import validate_code, validate_file
from rag.embeddings import BACKENDS
from rag.ingestion import ingest_knowledge_base, index_path
from rag.retriever import Retriever
from utils.files import numbered_html, soften

st.set_page_config(page_title="AI Code Review - Milestone 2", page_icon="🛡️", layout="wide")

# ---------------- sidebar: knowledge base ----------------
with st.sidebar:
    st.title("📚 RAG Knowledge Base")
    backend = st.selectbox("Vector search backend:", BACKENDS, help="TF-IDF works offline. Sentence-Transformers needs `pip install sentence-transformers`.")
    if st.button("🔄 Index Knowledge Base", use_container_width=True):
        with st.spinner("Loading, chunking, embedding and indexing..."):
            try:
                st.session_state["index_info"] = ingest_knowledge_base(backend=backend)
            except ImportError:
                st.error("sentence-transformers is not installed. Use TF-IDF or run: pip install sentence-transformers")
    info = st.session_state.get("index_info")
    if info and info["status"] == "ok":
        st.success(f"Indexed {info['docs_loaded']} documents → {info['chunks_created']} chunks")
        st.caption(f"Categories: {info['by_category']}")
        st.caption(f"Languages: {info['by_language']}")
    elif os.path.exists(index_path(backend)):
        st.info("An index already exists for this backend.")
    else:
        st.warning("No index yet. Click 'Index Knowledge Base'.")
    st.divider()
    st.subheader("🔎 Search the knowledge base")
    q = st.text_input("Ask a secure-coding question", placeholder="how to prevent SQL injection")
    q_lang = st.radio("Language filter", ["any", "python", "java"], horizontal=True)
    if q:
        hits = Retriever(backend).search(q, 4, None if q_lang == "any" else q_lang)
        for h in hits:
            with st.expander(f"{h['score']:.2f} · {h['title'][:45]}"):
                st.caption(f"{h['source']} · {h['category']} · {h['language']}")
                st.markdown(soften(h["text"], 600))
        if not hits:
            st.caption("No results (is the index built?).")

st.title("🛡️ AI Code Review & Security Analysis Agent")
st.caption("Milestone 2: Code Analysis Agent + Security Vulnerability Agent, run in parallel and merged into one report")

left, right = st.columns(2, gap="large")

# ---------------- left: submission ----------------
with left:
    st.header("1. Code Submission Module")
    up = st.file_uploader("Upload Python (.py) or Java (.java) file", type=None, help="Limit 500 KB per file; only .py and .java are accepted")
    pasted = st.text_area("Or paste source code here (Python / Java auto-detected):", height=330,
                          placeholder="Paste your Python or Java code here...")
    code, result, source, fname = "", None, None, None
    if up is not None:
        fname, source = up.name, "upload"
        result = validate_file(up.name, up.getvalue())
        code = result.get("code", "")
    elif pasted.strip():
        source = "paste"
        code = pasted
        result = validate_code(pasted)
    can_submit = bool(result and result["valid"])
    submit = st.button("✅ Validate Code & Run Analysis Agents", type="primary",
                       use_container_width=True, disabled=not can_submit,
                       help="Enabled only when the code has no syntax errors.")
    if result and not result["valid"]:
        st.caption("Submit is disabled until the syntax errors are fixed.")

# ---------------- right: output ----------------
with right:
    st.header("2. Validation & Agent Review Output")
    if result is None:
        st.info("Paste code or upload a `.py` / `.java` file on the left to auto-detect the language and validate syntax.")
    else:
        lang = result.get("language")
        c1, c2, c3 = st.columns(3)
        c1.metric("Language", (lang or "n/a").capitalize())
        c2.metric("Syntax", "Valid" if result["valid"] else "Errors")
        c3.metric("Source", (source or "").capitalize())
        if result["valid"]:
            st.success(f"No syntax errors found. Language detected via {result.get('detected_by', 'file extension')}.")
        else:
            where = f" on line {result['line']}" if result.get("line") else ""
            st.error(f"Syntax error{where}: {result['error']}")
        review_result = st.session_state.get("review") if st.session_state.get("review_code") == code else None
        if submit and can_submit:
            with st.spinner("Running the Code Analysis and Security Vulnerability agents in parallel..."):
                review_result = review(code, lang)
            st.session_state["review"], st.session_state["review_code"] = review_result, code
        if review_result is not None and can_submit:
            rv = review_result
            ca, cb = st.columns(2)
            for col, name in zip((ca, cb), rv.status):
                ok = rv.status[name] == "Complete"
                col.markdown(f"{'🟢' if ok else '🔴'} **{AGENT_LABEL[name]}** — {rv.status[name]} "
                             f"· {rv.by_agent[name]} findings · {rv.timings[name] * 1000:.0f} ms")
            for name, err in rv.errors.items():
                st.warning(f"{AGENT_LABEL[name]} failed ({err}). The other agent's results are still shown.")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Risk score", f"{rv.risk_score}/10")
            m2.metric("Code quality", f"{rv.quality_score}/100")
            m3.metric("Technical debt", f"{rv.technical_debt_minutes // 60}h {rv.technical_debt_minutes % 60}m")
            m4.metric("Findings", len(rv.findings))
            st.markdown(" ".join(f"`{k.title()}: {v}`" for k, v in rv.by_severity.items()))
            t_find, t_guide = st.tabs(["Review findings", "Retrieved guidelines (RAG)"])
            with t_find:
                f1, f2 = st.columns(2)
                pick_a = f1.multiselect("Agent", list(rv.by_agent), default=list(rv.by_agent), format_func=lambda a: AGENT_LABEL[a])
                pick_s = f2.multiselect("Severity", list(SEVERITY_ORDER), default=list(SEVERITY_ORDER))
                shown = [f for f in rv.findings if f.agent in pick_a and f.severity in pick_s]
                if not shown:
                    st.success("No findings for this filter.")
                for f in shown:
                    with st.expander(f"{f.severity} · {f.rule_id} · line {f.line} · {f.title}", expanded=(f.severity in ("CRITICAL", "HIGH") and f.id in [x.id for x in shown[:3]])):
                        st.markdown(f"**{f.message}**")
                        st.caption(f"{AGENT_LABEL[f.agent]} · score {f.score} · confidence {f.confidence}" + (f" · OWASP {f.owasp}" if f.owasp else "") + (f" · {f.cwe}" if f.cwe else ""))
                        st.markdown("**Evidence**"); st.code(f.snippet or "-", language=lang)
                        st.markdown(f"**Suggested remediation:** {f.fix_hint}")
                st.download_button("⬇️ Export findings (JSON)", json.dumps([f.to_dict() for f in rv.findings], indent=2),
                                   file_name="findings.json", mime="application/json")
            with t_guide:
                r = Retriever(backend)
                if not r.ready:
                    st.warning("Knowledge base is not indexed yet. Click 'Index Knowledge Base' in the sidebar, then submit again.")
                seen = set()
                for f in rv.findings:
                    if f.type in seen or not f.scored or not r.ready or len(seen) >= 8:
                        continue
                    seen.add(f.type)
                    hits = r.search(f"{f.title} {f.fix_hint} {f.cwe}", 1, lang)
                    if hits:
                        h = hits[0]
                        with st.expander(f"{f.rule_id} → {h['title'][:60]}"):
                            st.caption(f"{h['source']} · {h['category']} · relevance {h['score']:.2f}")
                            st.markdown(soften(h["text"], 700))

        if code:
            with st.expander("Code view with line numbers", expanded=True):
                flags = {}
                if review_result is not None and can_submit:
                    for f in reversed(review_result.findings):
                        flags[f.line] = (f.severity, f"{f.severity}: {f.title}")
                st.markdown(numbered_html(code, result.get("line"), flags=flags), unsafe_allow_html=True)

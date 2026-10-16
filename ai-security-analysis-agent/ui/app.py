"""AI Code Review & Security Analysis Agent - Milestone 1 dashboard.
Run from the project root:  streamlit run ui/app.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st
from parsers.validate import validate_code, validate_file
from rag.embeddings import BACKENDS
from rag.ingestion import ingest_knowledge_base, index_path
from rag.retriever import Retriever
from utils.files import numbered_html, soften

st.set_page_config(page_title="AI Code Review - Milestone 1", page_icon="🛡️", layout="wide")

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
st.caption("Milestone 1: Code Submission Module + Secure Coding Knowledge Base (RAG)")

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
    submit = st.button("✅ Validate Code & Retrieve Security Guidelines", type="primary",
                       use_container_width=True, disabled=not can_submit,
                       help="Enabled only when the code has no syntax errors.")
    if result and not result["valid"]:
        st.caption("Submit is disabled until the syntax errors are fixed.")

# ---------------- right: output ----------------
with right:
    st.header("2. Validation & RAG Knowledge Base Output")
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
        if submit and can_submit:
            r = Retriever(backend)
            if not r.ready:
                st.warning("Knowledge base is not indexed yet. Click 'Index Knowledge Base' in the sidebar, then submit again.")
            else:
                st.subheader("Potential issues and guidelines")
                st.caption("Pattern-based hints retrieved from the knowledge base. The full AI analysis agents arrive in Milestone 2.")
                issues = r.analyze_code(code, lang)
                if not issues:
                    st.success("No risky patterns matched. Showing general quality guidance instead.")
                    issues = [{"issue": "General code quality", "lines": [], "guidance": r.search(f"{lang} code quality best practices", 3, lang)}]
                for n, it in enumerate(issues):
                    ln = f" (line {', '.join(map(str, it['lines']))})" if it["lines"] else ""
                    with st.expander(f"⚠️ {it['issue']}{ln}", expanded=(n < 2)):
                        for h in it["guidance"]:
                            st.markdown(f"**{h['title']}**  \n`{h['source']}` · {h['category']} · relevance {h['score']:.2f}")
                            st.markdown(soften(h["text"], 700))
                            st.divider()

        if code:
            with st.expander("Code view with line numbers", expanded=not (submit and can_submit)):
                st.markdown(numbered_html(code, result.get("line")), unsafe_allow_html=True)

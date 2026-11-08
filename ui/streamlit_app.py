from __future__ import annotations

import json
import os
import uuid
from typing import Any

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
DEFAULT_API_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

st.set_page_config(page_title="CloudSentry AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
:root {
    --cs-bg: #0b1220;
    --cs-panel: #111c2e;
    --cs-panel2: #152238;
    --cs-line: #263750;
    --cs-muted: #91a4bf;
    --cs-text: #edf4ff;
    --cs-accent: #55d6be;
    --cs-blue: #74a7ff;
    --cs-danger: #ff6b6b;
    --cs-warn: #ffd166;
}
.stApp { background: radial-gradient(ellipse at 12% 0%, rgba(45,91,145,.18), transparent 35%), var(--cs-bg); color: var(--cs-text); font-family: 'DM Sans', sans-serif; }
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1480px; }
[data-testid="stSidebar"] { background: #0d1727; border-right: 1px solid var(--cs-line); }
[data-testid="stSidebar"] h1,[data-testid="stSidebar"] h2,[data-testid="stSidebar"] h3 { font-family: 'Space Grotesk', sans-serif; }
h1,h2,h3 { font-family: 'Space Grotesk', sans-serif !important; letter-spacing: -.025em; }

.hero {
    border: 1px solid #2b405c;
    border-radius: 20px;
    padding: 24px 28px;
    background: linear-gradient(115deg, rgba(28,57,87,.92), rgba(17,28,46,.95) 65%, rgba(19,55,61,.85));
    margin-bottom: 20px;
}
.hero-kicker { color: var(--cs-accent); font-size: .76rem; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
.hero-title { font-family: 'Space Grotesk', sans-serif; font-size: 2.1rem; line-height: 1.15; font-weight: 700; margin: .4rem 0 .5rem; color: #f2f7ff; }
.hero-sub { color: #b4c5dc; max-width: 820px; font-size: .98rem; }

[data-testid="stMetric"] { background: linear-gradient(145deg, #132239, #101a2b); border: 1px solid var(--cs-line); padding: 16px 18px; border-radius: 14px; }
[data-testid="stMetricLabel"] { color: #9db1cb; font-size: .84rem; }
[data-testid="stMetricValue"] { color: #f2f7ff; font-family: 'Space Grotesk', sans-serif; }

.stButton > button, .stDownloadButton > button { border-radius: 9px; border: 1px solid #314864; background: #182941; color: #eaf3ff; font-weight: 600; transition: all .15s ease; }
.stButton > button:hover { border-color: var(--cs-accent); color: var(--cs-accent); background: #1a3048; }
.stButton > button[kind="primary"] { background: var(--cs-accent); border-color: var(--cs-accent); color: #06241f; }

.stTextInput input, .stTextArea textarea, .stNumberInput input, .stDateInput input { background: #0d1828 !important; color: #eef5ff !important; border: 1px solid #2a3d57 !important; border-radius: 9px !important; }
[data-baseweb="select"] > div { background: #0d1828; border-color: #2a3d57; border-radius: 9px; }

[data-testid="stTabs"] [role="tab"] { padding: 10px 16px; font-weight: 600; font-size: .92rem; }
[data-testid="stTabs"] [aria-selected="true"] { color: var(--cs-accent) !important; border-bottom-color: var(--cs-accent) !important; }

div[data-testid="stExpander"] { border: 1px solid var(--cs-line); border-radius: 12px; background: rgba(17,28,46,.7); }
div[data-testid="stChatMessage"] { background: #111d30; border: 1px solid #263750; border-radius: 14px; padding: 12px 14px; }

.pill { display: inline-block; padding: 3px 9px; border-radius: 999px; border: 1px solid #31526b; background: #142b3a; color: #8ee7d4; font-size: .74rem; font-weight: 700; }
.pill-danger { border-color: #7a2828; background: #331313; color: #ff9494; }
.pill-warn { border-color: #6e5821; background: #2e2308; color: #ffd67a; }
.pill-info { border-color: #264a73; background: #122238; color: #9bc5ff; }

.auth-card { max-width: 520px; margin: 3vh auto; padding: 32px; border: 1px solid #2b405c; border-radius: 20px; background: linear-gradient(145deg, #132239, #0f1a2a); box-shadow: 0 12px 40px rgba(0,0,0,.4); }
hr { border-color: #263750 !important; }
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

if "api_url" not in st.session_state:
    st.session_state.api_url = DEFAULT_API_URL
if "token" not in st.session_state:
    st.session_state.token = ""
if "user" not in st.session_state:
    st.session_state.user = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "chat_session_id" not in st.session_state:
    st.session_state.chat_session_id = str(uuid.uuid4())


def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}


def _response_error(response: requests.Response) -> str:
    try:
        body = response.json()
        return str(body.get("detail", body))
    except Exception:
        return response.text[:400]


def api_get(path: str, **kwargs: Any) -> Any:
    response = requests.get(f"{st.session_state.api_url}{path}", headers=headers(), timeout=30, **kwargs)
    if response.status_code == 401:
        st.session_state.token = ""
        st.session_state.user = None
        raise RuntimeError("Session expired. Please sign in again.")
    if response.status_code >= 400:
        raise RuntimeError(f"API {response.status_code}: {_response_error(response)}")
    return response.json()


def api_post(path: str, **kwargs: Any) -> Any:
    response = requests.post(f"{st.session_state.api_url}{path}", headers=headers(), timeout=180, **kwargs)
    if response.status_code == 401:
        st.session_state.token = ""
        st.session_state.user = None
        raise RuntimeError("Session expired. Please sign in again.")
    if response.status_code >= 400:
        raise RuntimeError(f"API {response.status_code}: {_response_error(response)}")
    return response.json()


def api_patch(path: str, **kwargs: Any) -> Any:
    response = requests.patch(f"{st.session_state.api_url}{path}", headers=headers(), timeout=30, **kwargs)
    if response.status_code == 401:
        st.session_state.token = ""
        st.session_state.user = None
        raise RuntimeError("Session expired. Please sign in again.")
    if response.status_code >= 400:
        raise RuntimeError(f"API {response.status_code}: {_response_error(response)}")
    return response.json()


def login_screen() -> None:
    st.markdown('<div class="auth-card">', unsafe_allow_html=True)
    st.markdown('<div class="hero-kicker">CLOUDSENTRY AI · SECURE WORKSPACE</div>', unsafe_allow_html=True)
    st.markdown("## Cloud Security Intelligence")
    st.markdown('<p style="color:#9bb1cc;font-size:0.92rem;margin-bottom:1.2rem;">Sign in to investigate AWS CloudTrail telemetry, triage GuardDuty alerts, and chat with the AI copilot.</p>', unsafe_allow_html=True)

    mode = st.radio("Access mode", ["Sign in", "Create account"], horizontal=True, key="auth_mode")

    with st.form("auth_form", clear_on_submit=False):
        email = st.text_input("Work email", placeholder="analyst@company.com", key="auth_email")
        full_name = st.text_input("Full name", placeholder="Your name", key="auth_name") if mode == "Create account" else ""
        password = st.text_input(
            "Password",
            type="password",
            placeholder="At least 12 characters" if mode == "Create account" else "Enter password",
            key="auth_pass"
        )
        confirm = st.text_input("Confirm password", type="password", key="auth_confirm") if mode == "Create account" else password
        submit = st.form_submit_button("Create Account" if mode == "Create account" else "Sign In", type="primary", use_container_width=True)

    if submit:
        if not email or not password:
            st.error("Please provide both email and password.")
            return
        if mode == "Create account" and password != confirm:
            st.error("Passwords do not match.")
            return

        try:
            if mode == "Create account":
                result = api_post("/api/v1/auth/register", json={"email": email, "password": password, "full_name": full_name or "Analyst"})
                st.success("Account created successfully! Please switch to 'Sign in' above.")
            else:
                resp = requests.post(f"{st.session_state.api_url}/api/v1/auth/login", json={"email": email, "password": password}, timeout=25)
                if resp.status_code >= 400:
                    raise RuntimeError(_response_error(resp))
                data = resp.json()
                st.session_state.token = data["access_token"]
                st.session_state.user = data["user"]
                st.session_state.chat_history = []
                st.rerun()
        except Exception as exc:
            st.error(f"Authentication failed: {exc}")

    st.markdown("<hr>", unsafe_allow_html=True)
    st.caption("ℹ️ First registered account automatically receives the workspace administrator role.")
    st.markdown('</div>', unsafe_allow_html=True)


# Authentication Check
if not st.session_state.token:
    login_screen()
    st.stop()

try:
    me = api_get("/api/v1/auth/me").get("user")
    st.session_state.user = me
except Exception:
    st.session_state.token = ""
    st.session_state.user = None
    st.rerun()

user = st.session_state.user or {}
role = user.get("role", "analyst")

# Sidebar
with st.sidebar:
    st.markdown("### 🛡️ CloudSentry AI")
    st.markdown(f'<span class="pill">{role.upper()} WORKSPACE</span>', unsafe_allow_html=True)
    st.caption(f"Operator: **{user.get('full_name') or user.get('email')}**")
    st.divider()

    st.markdown("#### Telemetry Ingestion")
    scenario = st.selectbox("Sample scenario", ["suspicious", "benign", "mixed"], index=0, help="Simulated scenarios with no AWS charges.")
    if st.button("Load sample scenario", use_container_width=True, disabled=role == "viewer"):
        try:
            res = api_post("/api/v1/demo/load", json={"scenario": scenario})
            st.success(f"Added {res['new_events']:,} events.")
            st.rerun()
        except Exception as exc:
            st.error(str(exc))

    with st.expander("Upload audit logs (JSON/CSV/GZ)"):
        uploads = st.file_uploader("Upload logs", type=["json", "jsonl", "csv", "txt", "gz", "log"], accept_multiple_files=True, label_visibility="collapsed")
        if st.button("Ingest uploaded files", use_container_width=True, disabled=not uploads or role == "viewer"):
            for file in uploads or []:
                try:
                    res = api_post("/api/v1/ingest/upload", files={"file": (file.name, file.getvalue(), file.type or "application/octet-stream")})
                    st.success(f"{file.name}: {res['parsed_events']:,} parsed")
                except Exception as exc:
                    st.error(f"{file.name}: {exc}")
            st.rerun()

    with st.expander("AWS Read-Only Sync"):
        region = st.text_input("AWS region", value="ap-south-1")
        profile = st.text_input("AWS CLI profile (optional)", value=os.getenv("AWS_PROFILE", ""))
        params = {"region": region}
        if profile.strip():
            params["profile"] = profile.strip()
        if st.button("Check AWS connectivity", use_container_width=True):
            try:
                stat = api_get("/api/v1/aws/status", params=params)
                st.success(f"Account: {stat.get('account_id_masked')} ({region})")
                for s_name, s_stat in stat.get("services", {}).items():
                    st.caption(f"**{s_name}**: {s_stat.get('status')}")
            except Exception as exc:
                st.error(str(exc))

        hours = st.number_input("Lookback hours", 1, 2160, 24)
        if st.button("Sync CloudTrail Event History", use_container_width=True, disabled=role == "viewer"):
            try:
                res = api_post("/api/v1/aws/cloudtrail/sync", params={**params, "hours": int(hours), "limit": 500})
                st.success(f"Fetched {res['fetched_events']} events.")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))

    st.divider()

    # Quick Floating AI Assistant Drawer in sidebar
    with st.expander("💬 Real-Time Quick Assistant", expanded=False):
        st.caption("Ask quick questions about workspace data or platform features:")
        quick_q = st.text_input("Quick question", placeholder="e.g. How many failed logins?", key="sidebar_quick_q")
        if st.button("Ask Assistant", key="sidebar_ask_btn") and quick_q.strip():
            try:
                ans_placeholder = st.empty()
                stream_res = requests.post(
                    f"{st.session_state.api_url}/api/v1/chat/stream",
                    headers=headers(),
                    json={"question": quick_q, "session_id": st.session_state.chat_session_id, "history": []},
                    stream=True,
                    timeout=(10, 90)
                )
                stream_res.encoding = "utf-8"
                full_t = ""
                for line in stream_res.iter_lines(decode_unicode=True):
                    if not line or not line.startswith("data: "):
                        continue
                    j = json.loads(line[6:])
                    if j.get("error"):
                        raise RuntimeError(j["error"])
                    full_t += j.get("token", "")
                    ans_placeholder.markdown(full_t)
            except Exception as exc:
                st.error(f"Error: {exc}")

    st.divider()
    if st.button("Sign out", use_container_width=True):
        st.session_state.token = ""
        st.session_state.user = None
        st.session_state.chat_history = []
        st.rerun()

# Workspace Header
st.markdown("""
<div class="hero">
    <div class="hero-kicker">AWS CLOUD SECURITY INCIDENT OPERATIONS</div>
    <div class="hero-title">CloudSentry AI Defense Copilot</div>
    <div class="hero-sub">Autonomous triage, correlation of identity & audit anomalies, and grounded AI investigation for AWS CloudTrail, GuardDuty, and Security Hub.</div>
</div>
""", unsafe_allow_html=True)

try:
    health = api_get("/api/v1/health")
    events_response = api_get("/api/v1/events", params={"limit": 1000})
    incidents_response = api_get("/api/v1/incidents", params={"limit": 50})
    knowledge = api_get("/api/v1/knowledge")
except Exception as exc:
    st.error(f"Failed to load workspace data: {exc}")
    st.stop()

events = events_response.get("events", [])
incidents = incidents_response.get("incidents", [])

# Metrics
m1, m2, m3, m4 = st.columns(4)
m1.metric("Events In Workspace", f"{events_response.get('total_count', len(events)):,}")
m2.metric("Saved Investigations", f"{len(incidents):,}")
m3.metric("Indexed Knowledge Chunks", f"{knowledge.get('indexed_chunks', 0):,}")
m4.metric("AI Copilot Mode", str(health.get("llm_mode", "UNKNOWN")).upper())

st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

# Tabs
tabs = st.tabs(["Overview", "AI Copilot", "Event Explorer", "Investigations", "Knowledge Base", "Profile & Access"])

# TAB 1: OVERVIEW
with tabs[0]:
    c_left, c_right = st.columns([1.35, 1])
    with c_left:
        st.markdown("### Telemetry Feed")
        if events:
            df = pd.DataFrame([{
                "Time": e.get("event_time"),
                "Event": e.get("event_name"),
                "Principal": e.get("principal"),
                "Source IP": e.get("source_ip"),
                "Provider": e.get("provider"),
            } for e in events[:14]])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No events in this workspace yet. Load sample data or sync AWS from the sidebar.")

    with c_right:
        st.markdown("### Active Triage Incidents")
        if incidents:
            for inc in incidents[:4]:
                with st.container(border=True):
                    s_label = str(inc.get("severity", "unknown")).upper()
                    st.markdown(f"**{inc.get('title', 'Untitled')}**")
                    pill_class = "pill-danger" if s_label in ("CRITICAL", "HIGH") else "pill-warn"
                    st.markdown(f'<span class="pill {pill_class}">{s_label}</span> · Risk Score: <strong>{inc.get("risk_score", 0)}/100</strong>', unsafe_allow_html=True)
                    st.caption(str(inc.get("summary", ""))[:220])
        else:
            st.info("No incidents investigated yet. Click 'Investigate Latest Events' below.")

    st.markdown("### Quick Operations")
    b1, b2, b3 = st.columns(3)
    with b1:
        if st.button("⚡ Investigate Latest Events", use_container_width=True, disabled=not events or role == "viewer"):
            try:
                with st.spinner("Analyzing event sequences and correlating telemetry..."):
                    rep = api_post("/api/v1/incidents/investigate", json={"limit": 200, "title": "Workspace Triage Review"})
                    st.session_state["last_report"] = rep
                    st.success("Investigation complete! Navigate to the 'Investigations' tab.")
                    st.rerun()
            except Exception as exc:
                st.error(str(exc))
    with b2:
        if st.button("💬 Open AI Copilot", use_container_width=True):
            st.info("Switch to the 'AI Copilot' tab above to start asking questions.")
    with b3:
        if st.button("🔄 Refresh Telemetry", use_container_width=True):
            st.rerun()

    for n in health.get("notes", []):
        st.caption(f"ℹ️ {n}")

# TAB 2: AI COPILOT (REAL-TIME STREAMING CHATBOT)
with tabs[1]:
    st.markdown("### CloudSentry Real-Time AI Copilot")
    st.caption("Ask questions about your workspace telemetry, attack sequences, AWS runbooks, or platform navigation. Responses are streamed in real time.")

    # Suggested Prompts
    st.markdown("**Suggested Quick Prompts:**")
    p_cols = st.columns(3)
    prompts_list = [
        "Explain the highest-risk signals in my workspace",
        "How many failed ConsoleLogin events occurred?",
        "What should I verify after suspicious IAM privilege changes?",
        "Are there any root user or S3 public exposure events?",
        "How do I connect real AWS CloudTrail and S3 logs?",
        "What are the top source IP addresses and principals?",
    ]
    for idx, p_text in enumerate(prompts_list):
        with p_cols[idx % 3]:
            if st.button(p_text, key=f"copilot_prompt_{idx}", use_container_width=True):
                st.session_state["pending_chat_prompt"] = p_text

    st.markdown("---")

    # Render previous conversation
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Input Box
    chat_input = st.chat_input("Ask a security or platform question…")
    if st.session_state.get("pending_chat_prompt"):
        chat_input = st.session_state.pop("pending_chat_prompt")

    if chat_input:
        st.session_state.chat_history.append({"role": "user", "content": chat_input})
        with st.chat_message("user"):
            st.markdown(chat_input)

        with st.chat_message("assistant"):
            response_box = st.empty()
            accumulated = ""
            try:
                payload = {
                    "question": chat_input,
                    "session_id": st.session_state.chat_session_id,
                    "history": st.session_state.chat_history[-8:-1]
                }
                res = requests.post(
                    f"{st.session_state.api_url}/api/v1/chat/stream",
                    headers=headers(),
                    json=payload,
                    stream=True,
                    timeout=(10, 120)
                )
                if res.status_code >= 400:
                    raise RuntimeError(_response_error(res))

                res.encoding = "utf-8"
                for raw_line in res.iter_lines(decode_unicode=True):
                    if not raw_line or not raw_line.startswith("data: "):
                        continue
                    data = json.loads(raw_line[6:])
                    if data.get("error"):
                        raise RuntimeError(data["error"])
                    token = data.get("token", "")
                    accumulated += token
                    response_box.markdown(accumulated + "▌")

                response_box.markdown(accumulated or "No response received.")
                st.session_state.chat_history.append({"role": "assistant", "content": accumulated})
            except Exception as exc:
                response_box.error(f"Chat failed: {exc}")
                if st.session_state.chat_history and st.session_state.chat_history[-1]["role"] == "user":
                    st.session_state.chat_history.pop()

    if st.button("Clear Conversation", key="clear_chat_history"):
        st.session_state.chat_history = []
        st.session_state.chat_session_id = str(uuid.uuid4())
        st.rerun()

# TAB 3: EVENT EXPLORER
with tabs[2]:
    st.markdown("### Event Explorer & Threat Telemetry")
    f1, f2, f3, f4 = st.columns([1.2, 1, 1, 1])
    with f1:
        e_name_filter = st.text_input("Event name contains", placeholder="e.g. StopLogging, AssumeRole")
    with f2:
        prov_filter = st.selectbox("Provider", ["All", "aws", "guardduty", "securityhub", "uploaded"])
    with f3:
        princ_filter = st.text_input("Principal contains", placeholder="e.g. root, admin")
    with f4:
        ip_filter = st.text_input("Source IP contains", placeholder="e.g. 203.0.113")

    if st.button("Filter Events", type="primary"):
        f_params = {"limit": 1000}
        if e_name_filter:
            f_params["event_name"] = e_name_filter
        if prov_filter != "All":
            f_params["provider"] = prov_filter
        if princ_filter:
            f_params["principal"] = princ_filter
        if ip_filter:
            f_params["source_ip"] = ip_filter
        try:
            st.session_state["filtered_events"] = api_get("/api/v1/events", params=f_params).get("events", [])
        except Exception as exc:
            st.error(str(exc))

    curr_events = st.session_state.get("filtered_events", events)
    if curr_events:
        table_rows = []
        for e in curr_events:
            table_rows.append({
                "Event ID": e.get("event_id"),
                "Time": e.get("event_time"),
                "Event Name": e.get("event_name"),
                "Principal": e.get("principal"),
                "Source IP": e.get("source_ip"),
                "Region": e.get("region"),
                "Provider": e.get("provider"),
                "Error": e.get("error_code") or "None",
            })
        e_df = pd.DataFrame(table_rows)
        st.dataframe(e_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Export Events as CSV",
            e_df.to_csv(index=False).encode("utf-8"),
            file_name="cloudsentry_telemetry.csv",
            mime="text/csv"
        )
    else:
        st.info("No matching events found in workspace.")

# TAB 4: INVESTIGATIONS
with tabs[3]:
    st.markdown("### Incident Investigations & Hypotheses")
    if role != "viewer":
        with st.form("new_investigation_form"):
            inv_title = st.text_input("Investigation Title", value="Cloud Security Incident Triage")
            inv_limit = st.slider("Events to correlate", 10, 500, 200, step=10)
            inv_submit = st.form_submit_button("Run Investigation State Machine", type="primary")

        if inv_submit:
            try:
                with st.spinner("Executing LangGraph investigation workflow..."):
                    report = api_post("/api/v1/incidents/investigate", json={"limit": inv_limit, "title": inv_title})
                    st.session_state["last_report"] = report
            except Exception as exc:
                st.error(str(exc))

    active_report = st.session_state.get("last_report")
    if active_report:
        st.markdown(f"## {active_report.get('title')}")
        rc1, rc2, rc3 = st.columns(3)
        rc1.metric("Priority Severity", str(active_report.get("severity")).upper())
        rc2.metric("Heuristic Risk Score", f"{active_report.get('risk_score', 0)}/100")
        rc3.metric("Observed Signals", len(active_report.get("signals", [])))

        st.markdown("---")
        st.markdown(active_report.get("analysis_markdown", active_report.get("summary", "")))

        with st.expander("Inspected Knowledge Sources & Citations"):
            st.json(active_report.get("knowledge_sources", []))
        with st.expander("Full JSON Report Structure"):
            st.json(active_report)

    st.markdown("### Historical Investigation Archive")
    if incidents:
        for item in incidents:
            s_badge = str(item.get("severity", "LOW")).upper()
            with st.expander(f"{item.get('title')} · {s_badge} · Score {item.get('risk_score')}/100"):
                st.write(item.get("summary"))
                st.code(f"Incident ID: {item.get('incident_id')}")

# TAB 5: KNOWLEDGE BASE
with tabs[4]:
    st.markdown("### Security Knowledge Base (RAG)")
    st.write(f"**Indexed Chunks:** {knowledge.get('indexed_chunks', 0)} · **Files:** {knowledge.get('knowledge_files', 0)} · **Embedding Engine:** `{knowledge.get('embedding_mode')}`")

    if role != "viewer":
        k_c1, k_c2 = st.columns(2)
        with k_c1:
            if st.button("Index New Knowledge Documents", use_container_width=True):
                try:
                    res = api_post("/api/v1/knowledge/index", json={"force_reindex": False})
                    st.success(f"Indexed {res.get('chunks_indexed')} chunks.")
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))
        with k_c2:
            if st.button("Rebuild Entire Vector Store", use_container_width=True):
                try:
                    res = api_post("/api/v1/knowledge/index", json={"force_reindex": True})
                    st.success(f"Re-indexed {res.get('chunks_indexed')} chunks.")
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))

    st.markdown("#### Search Knowledge Guidance")
    k_query = st.text_input("Runbook search", placeholder="e.g. S3 bucket policy exposure, Root account credentials, StopLogging")
    if st.button("Search Runbooks", disabled=not k_query.strip()):
        try:
            k_res = api_get("/api/v1/knowledge/search", params={"q": k_query, "k": 5})
            for doc in k_res.get("results", []):
                with st.container(border=True):
                    st.markdown(f"**{doc.get('title')}** · `{doc.get('source')}`")
                    st.write(doc.get("content"))
                    if doc.get("source_url"):
                        st.markdown(f"[View Documentation Source]({doc['source_url']})")
        except Exception as exc:
            st.error(str(exc))

# TAB 6: PROFILE & RBAC
with tabs[5]:
    st.markdown("### Operator Profile & Permissions")
    pr_left, pr_right = st.columns([1, 1.2])
    with pr_left:
        st.markdown("#### Account Information")
        st.text_input("Email", value=user.get("email", ""), disabled=True)
        st.text_input("Active Role", value=role.title(), disabled=True)
        st.text_input("Account Identifier", value=user.get("id", ""), disabled=True)
        st.caption(f"Created: {user.get('created_at') or 'Session'}")

    with pr_right:
        st.markdown("#### Edit Profile")
        with st.form("update_profile_form"):
            new_name = st.text_input("Full Name", value=user.get("full_name", ""))
            if st.form_submit_button("Update Profile", type="primary"):
                try:
                    res = api_patch("/api/v1/auth/profile", json={"full_name": new_name})
                    st.session_state.user = res["user"]
                    st.success("Profile updated.")
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))

    if role == "admin":
        st.markdown("---")
        st.markdown("#### Administrator Account & Role Delegation")
        try:
            all_users = api_get("/api/v1/admin/users").get("users", [])
            if all_users:
                u_map = {f"{u.get('full_name')} ({u.get('email')}) — Role: {u.get('role')}": u for u in all_users}
                sel_label = st.selectbox("Select Account", list(u_map.keys()))
                sel_u = u_map[sel_label]
                sel_role = st.selectbox("Modify Role", ["admin", "analyst", "viewer"], index=["admin", "analyst", "viewer"].index(sel_u.get("role", "analyst")))
                if st.button("Apply Role Change", disabled=(sel_role == sel_u.get("role"))):
                    api_patch(f"/api/v1/admin/users/{sel_u['id']}/role", json={"role": sel_role})
                    st.success(f"Updated role for {sel_u.get('email')} to {sel_role}.")
                    st.rerun()
        except Exception as exc:
            st.error(str(exc))

st.markdown("<hr>", unsafe_allow_html=True)
st.caption("🛡️ CloudSentry AI · Defensive AWS Cloud Security Triage Platform · All operations are read-only and evidence-grounded.")

"""SentinelFlow SOC console (Streamlit).

Run from the project folder (so .streamlit/config.toml applies the theme):
    streamlit run app/streamlit_app.py
Needs the backend (uvicorn backend.main:app --host :: --port 8000) and, for the
primary engine, n8n with the SentinelFlow workflow active/published."""
import html
import json
import os
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")
N8N = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/soc-triage")
_n = urlparse(N8N)
N8N_HEALTH = f"{_n.scheme}://{_n.netloc}/healthz"
RESULTS = ROOT / "benchmark" / "results"

st.set_page_config(page_title="SentinelFlow SOC Triage", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")

# ------------------------------------------------------------------ design tokens
C = {"bg": "#0B1220", "panel": "#141E31", "panel2": "#1A2640", "line": "#24324D", "text": "#E6EBF2",
     "muted": "#8D9BB3", "accent": "#4C9AFF", "a": "#3FB68B", "h": "#E0A93B", "e": "#E5534B", "x": "#9B8AFB"}
ROUTES = {"AUTO_CLOSE": ("Auto-closed", C["a"], "A"), "ANALYST_REVIEW": ("Analyst review", C["h"], "H"),
          "ESCALATE": ("Escalated", C["e"], "E"), "EXCEPTION": ("Exception queue", C["x"], "E")}
PALETTE = ["#4C9AFF", "#E0A93B", "#3FB68B", "#C77DFF", "#E5534B", "#5FD3D3", "#F28FB1", "#A3B4CC"]
PENDING = ("PENDING_APPROVAL", "PENDING_ESCALATION", "EXCEPTION_QUEUE")
STEPS = [("related_alerts", "SIEM related-alert search", "tool"), ("correlation_agent", "Correlation agent", "agent"),
         ("ti_lookup", "Threat-intel lookup", "tool"), ("threat_intel_agent", "Threat intelligence agent", "agent"),
         ("asset_lookup", "CMDB asset lookup", "tool"), ("asset_context_agent", "Asset context agent", "agent"),
         ("risk_score", "Deterministic risk score", "policy"), ("risk_agent", "Risk and prioritisation agent", "agent"),
         ("summary_agent", "Incident summary agent", "agent"), ("route", "Policy router", "policy")]
KIND = {"tool": C["accent"], "agent": "#C77DFF", "policy": C["h"]}

st.markdown(f"""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
.block-container {{padding-top:1rem; padding-bottom:3rem; max-width:1520px;}}
header[data-testid="stHeader"] {{background:transparent; height:0;}}
[class*="st-key-card"] {{background:{C['panel']}; border:1px solid {C['line']}; border-radius:16px; padding:1rem 1.1rem;}}
.sf-top {{display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:.8rem;
  background:linear-gradient(90deg,{C['panel']},{C['panel2']}); border:1px solid {C['line']}; border-radius:16px;
  padding:.9rem 1.2rem; margin-bottom:.8rem;}}
.sf-brand {{display:flex; align-items:center; gap:.8rem;}}
.sf-logo {{width:2.3rem; height:2.3rem; border-radius:10px; display:grid; place-items:center; font-size:1.2rem;
  background:rgba(76,154,255,.15); border:1px solid rgba(76,154,255,.4);}}
.sf-name {{font-size:1.35rem; font-weight:700; letter-spacing:.2px; line-height:1.1;}}
.sf-sub {{color:{C['muted']}; font-size:.85rem;}}
.sf-pills {{display:flex; gap:.5rem; flex-wrap:wrap;}}
.pill {{display:inline-flex; align-items:center; gap:.45rem; padding:.28rem .75rem; border-radius:999px;
  font-size:.82rem; border:1px solid {C['line']}; background:{C['bg']};}}
.dot {{width:.55rem; height:.55rem; border-radius:50%; display:inline-block;}}
.kpi-grid {{display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:.75rem; margin:.2rem 0 .9rem;}}
.kpi {{background:{C['panel']}; border:1px solid {C['line']}; border-radius:16px; padding:.85rem 1rem; position:relative; overflow:hidden;}}
.kpi:before {{content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--c);}}
.kpi .l {{color:{C['muted']}; font-size:.82rem;}}
.kpi .v {{font-size:1.85rem; font-weight:600; font-variant-numeric:tabular-nums; line-height:1.2; margin-top:.15rem;}}
.kpi .s {{color:{C['muted']}; font-size:.76rem; margin-top:.1rem;}}
.ct {{font-weight:600; font-size:1rem; margin-bottom:.1rem;}}
.cs {{color:{C['muted']}; font-size:.82rem; margin-bottom:.55rem;}}
.route {{display:inline-flex; align-items:center; gap:.5rem; padding:.32rem .85rem; border-radius:999px;
  font-weight:600; font-size:.92rem; color:#fff;}}
.route b {{background:rgba(255,255,255,.22); border-radius:6px; padding:0 .4rem;}}
.tag {{display:inline-block; padding:.14rem .55rem; border-radius:999px; font-size:.78rem; margin:.12rem .3rem .12rem 0;
  background:rgba(76,154,255,.12); color:#A8C8FF; border:1px solid rgba(76,154,255,.25); text-decoration:none;}}
.tag.grey {{background:{C['bg']}; color:{C['muted']}; border-color:{C['line']};}}
.flag {{border-radius:12px; padding:.5rem .75rem; margin:.35rem 0; font-size:.86rem; line-height:1.4;}}
.flag.bad {{background:rgba(229,83,75,.09); border:1px solid rgba(229,83,75,.35);}}
.flag.good {{background:rgba(63,182,139,.08); border:1px solid rgba(63,182,139,.32);}}
.flag.warn {{background:rgba(224,169,59,.09); border:1px solid rgba(224,169,59,.35);}}
.step {{display:flex; align-items:center; gap:.65rem; padding:.42rem .1rem; border-bottom:1px solid {C['line']}; font-size:.88rem;}}
.step:last-child {{border-bottom:none;}}
.step .k {{font-size:.7rem; padding:.05rem .45rem; border-radius:999px; border:1px solid {C['line']}; color:{C['muted']};}}
.step .t {{margin-left:auto; color:{C['muted']}; font-variant-numeric:tabular-nums;}}
.prog {{height:6px; border-radius:99px; background:{C['bg']}; margin:.4rem 0 .6rem; overflow:hidden;}}
.prog > div {{height:100%; border-radius:99px; background:linear-gradient(90deg,{C['accent']},#C77DFF);}}
.lb-grid {{display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:.75rem;}}
.lb {{background:{C['panel']}; border:1px solid {C['line']}; border-radius:16px; padding:1rem; border-top:4px solid var(--c);}}
.lb .rank {{color:{C['muted']}; font-size:.8rem;}}
.lb .name {{font-weight:600; margin:.1rem 0 .4rem;}}
.lb .big {{font-size:2.1rem; font-weight:700; font-variant-numeric:tabular-nums;}}
.lb .row {{display:flex; justify-content:space-between; font-size:.84rem; padding:.18rem 0; color:{C['muted']};}}
.lb .row span:last-child {{color:{C['text']}; font-variant-numeric:tabular-nums;}}
.qrow {{display:flex; align-items:center; gap:.7rem; flex-wrap:wrap; padding:.5rem 0; border-bottom:1px solid {C['line']}; font-size:.88rem;}}
.empty {{text-align:center; padding:2.2rem 1rem; color:{C['muted']};}}
.empty .h {{color:{C['text']}; font-size:1.05rem; font-weight:600; margin-bottom:.3rem;}}
[data-testid="stButtonGroup"] > div {{flex-wrap:wrap; row-gap:.4rem;}}
@media (max-width: 700px) {{ .kpi .v {{font-size:1.45rem;}} .sf-name {{font-size:1.1rem;}} .lb .big {{font-size:1.6rem;}} }}
</style>""", unsafe_allow_html=True)

esc = html.escape


# ------------------------------------------------------------------ helpers
def api(method, path, **kw):
    timeout = kw.pop("timeout", 30)
    try:
        r = requests.request(method, BACKEND + path, timeout=timeout, **kw)
    except requests.RequestException:
        return None, f"The backend is not reachable at {BACKEND}. Start it with: uvicorn backend.main:app --host :: --port 8000"
    if r.status_code >= 400:
        try:
            return None, f"{r.status_code}: {r.json().get('detail', r.text)}"
        except ValueError:
            return None, f"{r.status_code}: {r.text[:300]}"
    return r.json(), None


@st.cache_data(ttl=10, show_spinner=False)
def n8n_up():
    try:
        return requests.get(N8N_HEALTH, timeout=1.5).ok
    except requests.RequestException:
        return False


_card_n = {"i": 0}


def card(name=""):
    _card_n["i"] += 1
    return st.container(key=f"card-{name}-{_card_n['i']}")


def title(t, sub=None):
    st.markdown(f'<div class="ct">{esc(t)}</div>' + (f'<div class="cs">{esc(sub)}</div>' if sub else ""),
                unsafe_allow_html=True)


def kpis(items):
    cells = "".join(f'<div class="kpi" style="--c:{c}"><div class="l">{esc(l)}</div><div class="v">{esc(str(v))}</div>'
                    f'<div class="s">{esc(s or "")}</div></div>' for l, v, s, c in items)
    st.markdown(f'<div class="kpi-grid">{cells}</div>', unsafe_allow_html=True)


def route_html(route):
    label, color, letter = ROUTES.get(route, ("In progress", "#4A5872", "…"))
    return f'<span class="route" style="background:{color}"><b>{letter}</b>{label}</span>'


def empty(head, body):
    st.markdown(f'<div class="empty"><div class="h">{esc(head)}</div>{body}</div>', unsafe_allow_html=True)


def style(fig, h=300, t=""):
    fig.update_layout(height=h, margin=dict(l=8, r=8, t=36 if t else 8, b=8), title=dict(text=t, font=dict(size=14)),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", colorway=PALETTE,
                      font=dict(family="IBM Plex Sans, system-ui, sans-serif", color=C["text"], size=12),
                      legend=dict(orientation="h", yanchor="top", y=-0.15, x=0, bgcolor="rgba(0,0,0,0)"),
                      hoverlabel=dict(bgcolor=C["panel2"], bordercolor=C["line"], font_color=C["text"]))
    fig.update_xaxes(gridcolor=C["line"], zerolinecolor=C["line"], linecolor=C["line"])
    fig.update_yaxes(gridcolor=C["line"], zerolinecolor=C["line"], linecolor=C["line"])
    return fig


def show(fig):
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


def pct(v):
    return "–" if v is None or pd.isna(v) else f"{float(v) * 100:.0f}%"


def to_float(s):
    return s.map(lambda v: 1.0 if v in (True, "True", "true", 1) else 0.0 if v in (False, "False", "false", 0) else None).astype(float)


def model_label(k):
    return MODELS.get(k, {}).get("label", k) if k else "–"


def model_color(k):
    keys = list(MODELS)
    return PALETTE[keys.index(k) % len(PALETTE)] if k in keys else C["muted"]


def open_case(cid):
    st.session_state["nav"] = "Case queue"
    st.session_state["open_case"] = cid


# ------------------------------------------------------------------ header
health, health_err = api("GET", "/health", timeout=3)
MODELS = (api("GET", "/models")[0] or {}) if health else {}
chain = (api("GET", "/audit/verify")[0] or {}) if health else {}
n8n_ok = n8n_up()


def status_pill(ok, label):
    color = C["a"] if ok else C["e"]
    return f'<span class="pill"><span class="dot" style="background:{color}"></span>{esc(label)}</span>'


st.markdown(f"""<div class="sf-top"><div class="sf-brand"><div class="sf-logo">🛡️</div><div>
<div class="sf-name">SentinelFlow</div><div class="sf-sub">Governed agentic alert triage for the security operations centre</div></div></div>
<div class="sf-pills">{status_pill(bool(health), "Backend " + ("online" if health else "offline"))}
{status_pill(n8n_ok, "n8n " + ("online" if n8n_ok else "offline"))}
{status_pill(chain.get("valid", False), "Audit chain " + ("intact" if chain.get("valid") else "unverified"))}</div></div>""",
            unsafe_allow_html=True)

if not health:
    with card("offline"):
        empty("The backend is offline", esc(health_err))
    st.stop()

st.session_state.setdefault("nav", "Overview")
st.session_state.setdefault("role", "L2_ANALYST")
st.session_state.setdefault("approver", "Demo Analyst")
nav_col, who_col = st.columns([5, 1.3], vertical_alignment="center")
with nav_col:
    st.segmented_control("Navigation", ["Overview", "Triage", "Case queue", "Model comparison", "Audit and governance"],
                         key="nav", label_visibility="collapsed")
with who_col:
    with st.popover(f"👤 {st.session_state['approver']} ({st.session_state['role'].replace('_', ' ').title()})",
                    width="stretch"):
        st.selectbox("Role", ["L1_ANALYST", "L2_ANALYST", "SOC_LEAD"], key="role",
                     help="L2 approves review and exception cases. Only the SOC lead approves escalations.")
        st.text_input("Your name (recorded in the audit trail)", key="approver")
page = st.session_state.get("nav") or "Overview"


COLS = {"case_id": "Case", "created_at": "Created", "rule": "Rule", "host": "Host", "model_label": "Model",
        "route_label": "Route", "status": "Status", "verdict": "Verdict", "priority": "Priority", "decided_by": "Decided by",
        "score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d")}


def load_cases():
    rows, err = api("GET", "/cases", params={"limit": 1000})
    if err:
        st.error(err)
        st.stop()
    df = pd.DataFrame(rows)
    if not df.empty:
        df["created"] = pd.to_datetime(df["created_at"], utc=True)
        df["route_label"] = df["route"].map(lambda r: ROUTES.get(r, ("In progress",))[0])
        df["model_label"] = df["model"].map(model_label)
    return df


# ------------------------------------------------------------------ case detail
def stepper_html(case):
    done = {s["step"]: s for s in (case or {}).get("state", {}).get("steps", [])}
    rows = []
    for key, label, kind in STEPS:
        s = done.get(key)
        dot, t = (C["line"], "waiting") if not s else ((C["a"], f"{s['seconds']:.1f}s") if s["ok"] else (C["e"], "failed"))
        rows.append(f'<div class="step"><span class="dot" style="background:{dot}"></span><span>{label}</span>'
                    f'<span class="k" style="border-color:{KIND[kind]}55;color:{KIND[kind]}">{kind}</span><span class="t">{t}</span></div>')
    n = len(done)
    head = f'<div class="ct">Agent pipeline</div><div class="cs">{n} of {len(STEPS)} steps complete</div>'
    note = ""
    if case and not case["state"]["validation"]["valid"]:
        note = '<div class="flag bad">Input validation failed, so the agents were never called. The alert went straight to the exception queue.</div>'
    return head + f'<div class="prog"><div style="width:{int(100 * n / len(STEPS))}%"></div></div>' + note + "".join(rows)


def gauge(score, route):
    color = ROUTES.get(route, (None, C["accent"]))[1]
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score or 0, number={"font": {"size": 42}},
        gauge={"axis": {"range": [0, 100], "tickcolor": C["muted"], "tickvals": [0, 30, 70, 100]},
               "bar": {"color": color, "thickness": 0.32}, "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
               "steps": [{"range": [0, 30], "color": "rgba(63,182,139,.16)"},
                         {"range": [30, 70], "color": "rgba(224,169,59,.16)"},
                         {"range": [70, 100], "color": "rgba(229,83,75,.16)"}]}))
    return style(fig, 210)


def render_case(case):
    stt = case["state"]
    route = (stt.get("route") or {}).get("route")
    summ = (stt["agents"].get("summary") or {}).get("output") or {}
    alert = stt.get("alert") or {}
    total_latency = sum(a.get("latency_s") or 0 for a in stt["agents"].values())

    with card("case-head"):
        a, b = st.columns([3, 1.2], vertical_alignment="center")
        a.markdown(f"### {esc(alert.get('rule_name') or 'Alert')}", unsafe_allow_html=True)
        a.markdown(f'<span class="tag grey">{esc(case["case_id"])}</span><span class="tag grey">{esc(str(alert.get("alert_id", "")))}</span>'
                   f'<span class="tag grey">host {esc(str(alert.get("host") or "–"))}</span>'
                   f'<span class="tag grey">{esc(model_label(case["model"]))}</span><span class="tag grey">via {esc(case["source"])}</span>',
                   unsafe_allow_html=True)
        b.markdown(f'<div style="text-align:right">{route_html(route)}<div class="cs" style="margin-top:.4rem">'
                   f'{esc(case["status"].replace("_", " ").title())}</div></div>', unsafe_allow_html=True)
        kpis([("Risk score", (stt.get("score") or {}).get("score", "–"), "deterministic, 0–100", C["accent"]),
              ("Verdict", (summ.get("verdict") or "–").replace("_", " "), "from the summary agent", C["x"]),
              ("Priority", summ.get("priority", "–"), "P1 is most urgent", C["e"]),
              ("Confidence", pct(summ.get("confidence")), "model self-assessed", C["h"]),
              ("Model time", f"{total_latency:.1f}s", "sum of five agent calls", C["a"])])
        r = stt.get("route")
        if r:
            reasons = "".join(f"<li>{esc(x)}</li>" for x in r["reasons"])
            st.markdown(f'<div class="flag {"warn" if r.get("policy_override") else "good"}"><b>Why this route</b><ul style="margin:.3rem 0 0">{reasons}</ul></div>',
                        unsafe_allow_html=True)

    left, right = st.columns([1.55, 1])
    with left:
        with card("summary"):
            title("Incident summary", summ.get("title") or None)
            if summ:
                st.write(summ.get("summary", ""))
                if summ.get("mitre_techniques"):
                    tags = "".join(f'<a class="tag" target="_blank" href="https://attack.mitre.org/techniques/{t["id"].replace(".", "/")}/">'
                                   f'{esc(t["id"])} {esc(t.get("name", ""))}</a>' for t in summ["mitre_techniques"])
                    st.markdown("**MITRE ATT&CK**<br>" + tags, unsafe_allow_html=True)
                if summ.get("open_questions"):
                    st.markdown("**Open questions for the analyst**\n" + "\n".join(f"- {q}" for q in summ["open_questions"]))
            else:
                empty("No AI summary for this case", "The Guardrails panel shows why it was handed to a human.")
        with card("actions"):
            title("Response actions", "Containment actions always need a recorded human approval")
            recs = summ.get("recommended_actions") or []
            if recs:
                st.dataframe(pd.DataFrame(recs), hide_index=True, width="stretch",
                             column_config={"high_impact": st.column_config.CheckboxColumn("High impact")})
            else:
                st.caption("No actions recommended.")
            if stt.get("actions_executed"):
                st.markdown("**Executed**")
                st.dataframe(pd.DataFrame(stt["actions_executed"])[["ts", "action", "target", "system", "actor", "status"]],
                             hide_index=True, width="stretch")
            if stt.get("decision"):
                d = stt["decision"]
                st.markdown(f'<div class="flag good">Human decision: <b>{esc(d["decision"])}</b> by {esc(d["approver"])} '
                            f'({esc(d["role"])}) at {esc(d["ts"])}. {esc(d.get("comment") or "")}</div>', unsafe_allow_html=True)
    with right:
        with card("risk"):
            title("Risk assessment", "Bands: auto-close below 30, review 30–69, escalate from 70")
            sc = stt.get("score")
            if sc:
                show(gauge(sc["score"], route))
                comp = sc["components"]
                fig = go.Figure(go.Bar(x=[v["points"] for v in comp.values()],
                                       y=[f"{k.replace('_', ' ')} ({v['value']})" for k, v in comp.items()],
                                       orientation="h", marker_color=C["accent"], text=[v["points"] for v in comp.values()],
                                       textposition="auto"))
                show(style(fig, 190))
                for a in sc["assumptions"]:
                    st.caption(f"Assumption: {a}")
            else:
                empty("No score", "Scoring needs a valid alert.")
        with card("guard"):
            title("Guardrails", "Checks that ran on this case")
            v = stt["validation"]
            red = v.get("redactions", {})
            out = [f'<div class="flag {"good" if v["valid"] else "bad"}">Input validation: {"passed" if v["valid"] else esc("; ".join(v["errors"]))}</div>',
                   f'<div class="flag good">Masking: {red.get("emails", 0)} e-mail(s) and {red.get("secrets", 0)} secret(s) redacted before any model call</div>']
            for m in v["injection_matches"]:
                out.append(f'<div class="flag bad">Prompt injection in log content: <code>{esc(m)}</code></div>')
            for name, ag in stt["agents"].items():
                out += [f'<div class="flag bad">Grounding ({esc(name)}): {esc(h)} (removed)</div>' for h in ag.get("hallucinations") or []]
                out += [f'<div class="flag bad">Allowlist ({esc(name)}): {esc(b)} (blocked)</div>' for b in ag.get("blocked") or []]
            out += [f'<div class="flag warn">Context gap: {esc(g)}</div>' for g in stt.get("gaps", [])]
            st.markdown("".join(out), unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1.55])
    with c1:
        with card("pipe"):
            st.markdown(stepper_html(case), unsafe_allow_html=True)
    with c2:
        with card("trace"):
            title("Agent trace", "Validated output and the raw model reply for every agent")
            if not stt["agents"]:
                st.caption("No agents ran.")
            for name, ag in stt["agents"].items():
                icon = "✅" if ag["ok"] else "❌"
                with st.expander(f"{icon} {name}  ·  prompt {ag['prompt_version']}  ·  {ag['latency_s']}s  ·  attempts {ag['attempts']}"):
                    st.json(ag.get("output") or {"error": ag.get("error"), "errors": ag.get("errors")})
                    if ag.get("raw"):
                        st.caption("Raw model reply")
                        st.code(ag["raw"][:3000])
            with st.expander("Evidence given to the agents"):
                for ev in stt["evidence"]:
                    st.markdown(f"**{ev['id']}** ({ev['type']})")
                    st.json(ev["data"], expanded=False)
            with st.expander("Audit trail for this case"):
                aud, _ = api("GET", "/audit", params={"case_id": case["case_id"]})
                if aud:
                    st.dataframe(pd.DataFrame(aud)[["ts", "event", "actor", "model"]], hide_index=True, width="stretch")
    hitl_panel(case)


def hitl_panel(case):
    stt = case["state"]
    if case["status"] not in PENDING:
        return
    with card("hitl"):
        required = stt.get("required_role") or "L2_ANALYST"
        role = st.session_state["role"]
        allowed = {"L1_ANALYST": 1, "L2_ANALYST": 2, "SOC_LEAD": 3}[role] >= {"L1_ANALYST": 1, "L2_ANALYST": 2, "SOC_LEAD": 3}[required]
        title("Human decision required",
              f"Needs {required.replace('_', ' ').title()} or higher. You are acting as {role.replace('_', ' ').title()}.")
        if not allowed:
            st.markdown('<div class="flag warn">Your role cannot approve or reject this case. You can still escalate it, '
                        'or switch role with the button at the top right.</div>', unsafe_allow_html=True)
        recs = ((stt["agents"].get("summary") or {}).get("output") or {}).get("recommended_actions") or []
        chosen = []
        for i, a in enumerate(recs):
            tag = "⚠️ High impact: " if a.get("high_impact") else ""
            if st.checkbox(f"{tag}{a['action']} → {a['target']}  ({a.get('justification', '')})",
                           value=not a.get("high_impact"), key=f"{case['case_id']}-act-{i}"):
                chosen.append(i)
        c1, c2 = st.columns([1, 2])
        decision = c1.radio("Decision", ["approve", "reject", "escalate"], key=f"{case['case_id']}-dec",
                            help="Approve runs only the ticked actions. Reject closes the case. Escalate hands it to the SOC lead.")
        comment = c2.text_area("Comment for the audit trail", key=f"{case['case_id']}-comment", height=110)
        if st.button("Submit decision", type="primary", key=f"{case['case_id']}-submit"):
            res, err = api("POST", f"/cases/{case['case_id']}/decision", timeout=30,
                           json={"decision": decision, "approver": st.session_state["approver"], "role": role,
                                 "approved_actions": chosen, "comment": comment})
            if err:
                st.error(err)
            else:
                st.success(f"Decision recorded: {res.get('status', '').replace('_', ' ').lower()}")
                time.sleep(1.2)
                st.rerun()


# ================================================================== pages
if page == "Overview":
    df = load_cases()
    if df.empty:
        with card("empty"):
            empty("No alerts triaged yet", "Open the Triage tab and run a test case to populate the dashboard.")
        st.stop()
    routed = df[df["route"].notna()]
    n = len(df)
    auto = int((df["route"] == "AUTO_CLOSE").sum())
    pend = int(df["status"].isin(PENDING).sum())
    lat = df.loc[df["latency_s"] > 0, "latency_s"]
    kpis([("Alerts triaged", n, f"{len(routed)} routed", C["accent"]),
          ("Automation rate", pct(auto / n), f"{auto} auto-closed", C["a"]),
          ("Awaiting a human", pend, "review, escalation or exception", C["h"]),
          ("Escalated", int((df["route"] == "ESCALATE").sum()), "to the IR lead", C["e"]),
          ("Exceptions", int((df["route"] == "EXCEPTION").sum()), "incomplete context", C["x"]),
          ("Median model time", f"{lat.median():.1f}s" if not lat.empty else "–", "per alert, five agents", C["accent"]),
          ("Policy overrides", int(df["policy_override"].sum()), "policy beat the model", C["h"])])

    c1, c2 = st.columns([1, 1.8])
    with c1:
        with card("mix"):
            title("Routing mix", "A = autonomous, H = human review, E = escalation or exception")
            counts = routed["route"].value_counts()
            fig = go.Figure(go.Pie(labels=[ROUTES[r][0] for r in counts.index], values=counts.values, hole=.64,
                                   marker=dict(colors=[ROUTES[r][1] for r in counts.index], line=dict(color=C["panel"], width=3)),
                                   textinfo="value", sort=False, textfont=dict(color="#fff", size=13)))
            fig.add_annotation(text=f"<b>{len(routed)}</b><br>alerts", showarrow=False, font=dict(size=16, color=C["text"]))
            show(style(fig, 290))
    with c2:
        with card("time"):
            title("Alert volume over time", "Stacked by route")
            span = (df["created"].max() - df["created"].min()).total_seconds() / 3600
            freq = "15min" if span <= 6 else "h" if span <= 72 else "D"
            t = routed.assign(bucket=routed["created"].dt.floor(freq)).groupby(["bucket", "route"]).size().unstack(fill_value=0)
            fig = go.Figure([go.Bar(x=t.index, y=t[r], name=ROUTES[r][0], marker_color=ROUTES[r][1]) for r in t.columns])
            fig.update_layout(barmode="stack", bargap=.25)
            show(style(fig, 290))

    c1, c2, c3 = st.columns(3)
    with c1:
        with card("hist"):
            title("Risk score distribution", "Dashed lines mark the 30 and 70 thresholds")
            sc = routed[routed["score"].notna()]
            fig = go.Figure([go.Histogram(x=g["score"], name=ROUTES[r][0], marker_color=ROUTES[r][1],
                                          xbins=dict(start=0, end=100, size=10)) for r, g in sc.groupby("route")])
            for x in (30, 70):
                fig.add_vline(x=x, line_dash="dash", line_color=C["muted"])
            fig.update_layout(barmode="stack")
            fig.update_xaxes(range=[0, 100])
            show(style(fig, 280))
    with c2:
        with card("guards"):
            title("Guardrail activity", "Times a control intervened")
            g = {"Injection flagged": int(df["injection"].sum()), "Hallucinations removed": int(df["hallucinations"].sum()),
                 "Actions blocked": int(df["blocked"].sum()), "Policy overrides": int(df["policy_override"].sum()),
                 "Context gaps": int((df["gaps"] > 0).sum()), "Agent failures": int(df["agent_failures"].sum())}
            fig = go.Figure(go.Bar(x=list(g.values()), y=list(g.keys()), orientation="h", text=list(g.values()),
                                   textposition="auto", marker_color=[C["e"], C["x"], C["e"], C["h"], C["h"], C["muted"]]))
            fig.update_yaxes(autorange="reversed")
            show(style(fig, 280))
    with c3:
        with card("mitre"):
            title("Top MITRE ATT&CK techniques", "Across all agent outputs")
            m = df["mitre"].explode().dropna().value_counts().head(8)
            if m.empty:
                empty("No techniques yet", "")
            else:
                fig = go.Figure(go.Bar(x=m.values, y=m.index, orientation="h", marker_color="#C77DFF", text=m.values,
                                       textposition="auto"))
                fig.update_yaxes(autorange="reversed")
                show(style(fig, 280))

    c1, c2 = st.columns([1, 1.6])
    with c1:
        with card("pending"):
            title("Waiting for a human", "Highest risk first")
            pq = df[df["status"].isin(PENDING)].sort_values("score", ascending=False, na_position="last").head(6)
            if pq.empty:
                empty("Queue is clear", "Nothing needs a decision right now.")
            for _, r in pq.iterrows():
                a, b = st.columns([4, 1], vertical_alignment="center")
                a.markdown(f'<div class="qrow">{route_html(r["route"])}<span><b>{esc(str(r["rule"]))}</b><br>'
                           f'<span class="cs">{esc(r["case_id"])} · score {r["score"] if pd.notna(r["score"]) else "–"}</span></span></div>',
                           unsafe_allow_html=True)
                b.button("Open", key=f"open-{r['case_id']}", on_click=open_case, args=(r["case_id"],), width="stretch")
    with c2:
        with card("recent"):
            title("Recent cases")
            view = df.sort_values("created", ascending=False).head(15)
            st.dataframe(view[["case_id", "created_at", "rule", "host", "model_label", "score", "route_label", "status", "priority"]],
                         hide_index=True, width="stretch", height=380,
                         column_config=COLS)

elif page == "Triage":
    tcs, err = api("GET", "/test-cases")
    if err:
        st.error(err)
        st.stop()
    left, right = st.columns([1.35, 1])
    with left:
        with card("form"):
            title("Triage an alert", "Choose a test case or paste your own alert, then pick a model and engine")
            options = [f"{t['case_ref']} · {t['category']} · {t['title']}" for t in tcs] + ["Custom alert (paste JSON)"]
            choice = st.selectbox("Alert", options)
            if choice.startswith("Custom"):
                txt = st.text_area("Alert JSON", height=240, value=json.dumps(tcs[0]["alert"], indent=2))
                try:
                    alert = json.loads(txt)
                except json.JSONDecodeError as e:
                    alert = txt
                    st.warning(f"Not valid JSON ({e}). It will be sent anyway so you can see the exception path.")
            else:
                tc = tcs[options.index(choice)]
                alert = tc["alert"]
                a, b = st.columns(2)
                with a.expander("Alert payload"):
                    st.json(alert)
                with b.expander("Expected outcome (never shown to the agents)"):
                    st.json(tc["ground_truth"])
            keys = list(MODELS)
            default = health.get("default_model")
            c1, c2 = st.columns(2)
            model = c1.selectbox("Model", keys, index=keys.index(default) if default in keys else 0,
                                 format_func=model_label)
            engine = c2.radio("Engine", ["n8n workflow", "Python engine"], horizontal=True,
                              help="The Python engine runs the same steps without n8n (fallback).")
            run = st.button("Run triage", type="primary", width="stretch")
    with right:
        with card("progress"):
            pipe = st.empty()
            last = st.session_state.get("last_case")
            existing = api("GET", f"/cases/{last}", timeout=5)[0] if last else None
            pipe.markdown(stepper_html(existing), unsafe_allow_html=True)

    if run:
        case_id = f"CASE-{time.strftime('%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        st.session_state["last_case"] = case_id
        if engine == "n8n workflow":
            try:
                requests.post(N8N, json={"case_id": case_id, "model": model, "alert": alert}, timeout=15).raise_for_status()
            except requests.RequestException as e:
                st.error(f"The n8n webhook failed ({e}). Check that n8n is running and the workflow is active or published, "
                         f"or switch to the Python engine.")
                st.stop()
            for _ in range(900):
                case, _ = api("GET", f"/cases/{case_id}", timeout=5)
                if case:
                    pipe.markdown(stepper_html(case), unsafe_allow_html=True)
                    if case["status"] != "RUNNING":
                        break
                time.sleep(0.5)
        else:
            with st.spinner("Agents working…"):
                _, err = api("POST", "/triage", timeout=900, json={"alert": alert, "model": model, "case_id": case_id})
            if err:
                st.error(err)
        st.rerun()

    if st.session_state.get("last_case"):
        case, _ = api("GET", f"/cases/{st.session_state['last_case']}")
        if case:
            render_case(case)

elif page == "Case queue":
    df = load_cases()
    if df.empty:
        with card("empty"):
            empty("No cases yet", "Triage an alert to create one.")
        st.stop()
    with card("filters"):
        title("Case queue", f"{len(df)} cases in total, {int(df['status'].isin(PENDING).sum())} waiting for a human")
        f1, f2, f3, f4 = st.columns([1.3, 1.3, 1.3, 1.5])
        only = f1.toggle("Only cases waiting for a human", value=not st.session_state.get("open_case"))
        routes = f2.multiselect("Route", list(ROUTES), format_func=lambda r: ROUTES[r][0])
        mods = f3.multiselect("Model", sorted(df["model"].unique()), format_func=model_label)
        q = f4.text_input("Search rule, host or case ID")
        view = df.copy()
        if only:
            view = view[view["status"].isin(PENDING)]
        if routes:
            view = view[view["route"].isin(routes)]
        if mods:
            view = view[view["model"].isin(mods)]
        if q:
            ql = q.lower()
            view = view[view[["rule", "host", "case_id"]].astype(str).apply(lambda s: s.str.lower().str.contains(ql, regex=False)).any(axis=1)]
        view = view.sort_values("created", ascending=False)
        st.dataframe(view[["case_id", "created_at", "rule", "host", "model_label", "score", "route_label", "status",
                           "verdict", "priority", "decided_by"]],
                     hide_index=True, width="stretch", height=320,
                     column_config=COLS)
        ids = list(view["case_id"])
        target = st.session_state.get("open_case")
        if target and target not in ids and target in set(df["case_id"]):
            ids = [target] + ids
    if ids:
        sel = st.selectbox("Open case", ids, index=ids.index(target) if target in ids else 0)
        case, _ = api("GET", f"/cases/{sel}")
        if case:
            render_case(case)
    else:
        with card("noresult"):
            empty("No cases match these filters", "Clear a filter or turn off the waiting-for-a-human toggle.")

elif page == "Model comparison":
    st.session_state.setdefault("cmp", "Benchmark results")
    st.segmented_control("Comparison view", ["Benchmark results", "Head-to-head", "Live performance"], key="cmp",
                         label_visibility="collapsed")
    view = st.session_state.get("cmp") or "Benchmark results"

    if view == "Benchmark results":
        runs = sorted([p for p in RESULTS.glob("summary_*.csv") if p.stem != "summary_latest"], reverse=True)
        if not runs:
            with card("nobench"):
                empty("No benchmark results yet",
                      "Run <code>python -m benchmark.run_benchmark --models gptoss qwen llama-local --runs 3</code> "
                      "from the project folder, then refresh this page.")
            st.stop()

        def run_label(p):
            ts = p.stem.replace("summary_", "")
            raw = p.with_name(p.name.replace("summary_", "raw_"))
            pv = ""
            if raw.exists():
                try:
                    pv = f" · prompt {pd.read_csv(raw, usecols=['prompt_version'])['prompt_version'].iloc[0]}"
                except Exception:
                    pv = ""
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}{pv}"

        with card("runsel"):
            a, b = st.columns([2, 1], vertical_alignment="bottom")
            sel = a.selectbox("Benchmark run", runs, format_func=run_label)
            s = pd.read_csv(sel).sort_values("composite_score", ascending=False)
            raw_p = sel.with_name(sel.name.replace("summary_", "raw_"))
            raw = pd.read_csv(raw_p) if raw_p.exists() else None
            b.download_button("Download summary CSV", sel.read_bytes(), file_name=sel.name, width="stretch")
            st.caption("Every model saw the same cases, prompts, evidence and output schema. "
                       f"{int(s['runs'].iloc[0])} runs per model.")

        cells = []
        for rank, (_, r) in enumerate(s.iterrows(), 1):
            col = model_color(r["model"])
            cells.append(f'<div class="lb" style="--c:{col}"><div class="rank">Rank {rank}</div><div class="name">{esc(str(r["label"]))}</div>'
                         f'<div class="big">{r["composite_score"] * 100:.0f}<span class="cs"> / 100 composite</span></div>'
                         f'<div class="row"><span>Verdict accuracy</span><span>{pct(r["verdict_accuracy"])}</span></div>'
                         f'<div class="row"><span>Escalation accuracy</span><span>{pct(r["model_escalation_accuracy"])}</span></div>'
                         f'<div class="row"><span>Critical misses</span><span>{pct(r["critical_miss_rate"])}</span></div>'
                         f'<div class="row"><span>Hallucination rate</span><span>{pct(r["hallucination_rate"])}</span></div>'
                         f'<div class="row"><span>Median latency</span><span>{r["median_latency_s"]:.1f}s</span></div></div>')
        st.markdown(f'<div class="lb-grid">{"".join(cells)}</div>', unsafe_allow_html=True)
        st.write("")

        c1, c2 = st.columns(2)
        with c1:
            with card("radar"):
                title("Quality profile", "Higher is better on every axis")
                q = ["verdict_accuracy", "priority_accuracy", "model_escalation_accuracy", "schema_compliance",
                     "injection_resistance", "consistency", "mitre_recall"]
                fig = go.Figure()
                for _, r in s.iterrows():
                    vals = [float(r[k]) if pd.notna(r[k]) else 0 for k in q]
                    fig.add_trace(go.Scatterpolar(r=vals + vals[:1], theta=[k.replace("_", " ") for k in q + q[:1]],
                                                  fill="toself", name=r["label"], line_color=model_color(r["model"]), opacity=.75))
                fig.update_layout(polar=dict(bgcolor="rgba(0,0,0,0)", radialaxis=dict(range=[0, 1], gridcolor=C["line"]),
                                             angularaxis=dict(gridcolor=C["line"])))
                style(fig, 400).update_layout(margin=dict(l=60, r=60, t=30, b=30))
                show(fig)
        with c2:
            with card("bubble"):
                title("Accuracy against speed", "Top left is best. Bubble size is the composite score.")
                fig = go.Figure()
                for _, r in s.iterrows():
                    fig.add_trace(go.Scatter(x=[r["median_latency_s"]], y=[r["verdict_accuracy"]], mode="markers+text",
                                             text=[r["label"]], textposition="top center", name=r["label"],
                                             marker=dict(size=18 + 50 * float(r["composite_score"]), color=model_color(r["model"]),
                                                         opacity=.8, line=dict(color=C["text"], width=1))))
                fig.update_xaxes(title="Median pipeline latency (s)")
                fig.update_yaxes(title="Verdict accuracy", range=[-0.05, 1.12], tickformat=".0%")
                fig.update_layout(showlegend=False)
                show(style(fig, 400))

        c1, c2 = st.columns(2)
        with c1:
            with card("acc"):
                title("Decision accuracy", "Against the labelled ground truth")
                mets = {"verdict_accuracy": "Verdict", "priority_accuracy": "Priority",
                        "model_escalation_accuracy": "Model's route", "system_route_accuracy": "Final route (with policy)"}
                fig = go.Figure([go.Bar(name=r["label"], x=list(mets.values()), y=[r[k] for k in mets],
                                        marker_color=model_color(r["model"])) for _, r in s.iterrows()])
                fig.update_yaxes(range=[0, 1.05], tickformat=".0%")
                show(style(fig, 330))
        with c2:
            with card("err"):
                title("Error rates", "Lower is better. Critical misses are the costliest.")
                mets = {"critical_miss_rate": "Critical misses", "false_positive_rate": "False positives",
                        "hallucination_rate": "Hallucinations"}
                fig = go.Figure([go.Bar(name=r["label"], x=list(mets.values()), y=[r[k] if pd.notna(r[k]) else 0 for k in mets],
                                        marker_color=model_color(r["model"])) for _, r in s.iterrows()])
                fig.update_yaxes(tickformat=".0%", rangemode="tozero")
                show(style(fig, 330))

        if raw is not None:
            c1, c2 = st.columns([1.4, 1])
            with c1:
                with card("heat"):
                    title("Per-case results", "Share of runs that were correct for each case and model")
                    metric = st.radio("Metric", ["verdict_correct", "model_route_correct", "system_route_correct"],
                                      horizontal=True, format_func=lambda m: m.replace("_", " ").capitalize(),
                                      label_visibility="collapsed")
                    hm = raw.assign(v=to_float(raw[metric])).pivot_table(index="case_ref", columns="model", values="v", aggfunc="mean")
                    fig = go.Figure(go.Heatmap(z=hm.values, x=[model_label(m) for m in hm.columns], y=hm.index, zmin=0, zmax=1,
                                               colorscale=[[0, C["e"]], [.5, C["h"]], [1, C["a"]]],
                                               text=[[("–" if pd.isna(v) else f"{v:.0%}") for v in row] for row in hm.values],
                                               texttemplate="%{text}", showscale=False, xgap=3, ygap=3))
                    fig.update_yaxes(autorange="reversed")
                    show(style(fig, 360))
            with c2:
                with card("rel"):
                    title("Reliability", "Schema compliance, run-to-run consistency, task completion")
                    mets = {"schema_compliance": "Schema", "consistency": "Consistency", "task_completion": "Completion",
                            "injection_resistance": "Injection resistance"}
                    fig = go.Figure([go.Bar(name=r["label"], y=list(mets.values()), x=[r[k] if pd.notna(r[k]) else 0 for k in mets],
                                            orientation="h", marker_color=model_color(r["model"])) for _, r in s.iterrows()])
                    fig.update_xaxes(range=[0, 1.05], tickformat=".0%")
                    show(style(fig, 360))
            with card("rawtable"):
                with st.expander("All runs (raw results)"):
                    st.dataframe(raw, hide_index=True, width="stretch")

    elif view == "Head-to-head":
        tcs, _ = api("GET", "/test-cases")
        with card("h2hform"):
            title("Head-to-head", "Run one alert through several models and compare their decisions side by side")
            options = [f"{t['case_ref']} · {t['category']} · {t['title']}" for t in tcs]
            a, b = st.columns([1.2, 1.5])
            choice = a.selectbox("Alert", options, index=5 if len(options) > 5 else 0)
            real = [k for k, v in MODELS.items() if v["provider"] != "mock"]
            picks = b.multiselect("Models (two to four)", real, default=real[:3], format_func=model_label, max_selections=4)
            go_btn = st.button("Run head-to-head", type="primary", disabled=len(picks) < 2)
        if go_btn:
            tc = tcs[options.index(choice)]
            ids = []
            prog = st.progress(0.0, text="Starting")
            for i, m in enumerate(picks):
                prog.progress(i / len(picks), text=f"Running {model_label(m)}")
                cid = f"CMP-{time.strftime('%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
                _, err = api("POST", "/triage", timeout=900, json={"alert": tc["alert"], "model": m, "case_id": cid})
                if err:
                    st.error(f"{model_label(m)}: {err}")
                ids.append(cid)
            prog.empty()
            st.session_state["h2h"] = {"ids": ids, "gt": tc["ground_truth"], "ref": tc["case_ref"]}
        h2h = st.session_state.get("h2h")
        if h2h:
            cases = [c for c in (api("GET", f"/cases/{i}")[0] for i in h2h["ids"]) if c]
            gt = h2h["gt"]
            routes = {c["route"] for c in cases}
            agree = len(routes) == 1
            st.markdown(f'<div class="flag {"good" if agree else "warn"}">{h2h["ref"]}: models '
                        f'{"agree on the final route" if agree else "reach different final routes"}. '
                        f'Expected route: <b>{esc(str(gt["route"]))}</b>, expected verdict: <b>{esc(str(gt["verdict"]))}</b>.</div>',
                        unsafe_allow_html=True)
            cols = st.columns(len(cases))
            rows = []
            for col, c in zip(cols, cases):
                stt = c["state"]
                summ = (stt["agents"].get("summary") or {}).get("output") or {}
                lat = sum(a.get("latency_s") or 0 for a in stt["agents"].values())
                flags = sum(len(a.get("hallucinations") or []) + len(a.get("blocked") or []) for a in stt["agents"].values())
                ok = lambda v: "✅" if v else "❌"
                rows.append({"model": c["model"], "latency": lat, "confidence": summ.get("confidence") or 0})
                with col:
                    with card(f"h2h-{c['model']}"):
                        st.markdown(f'<div class="ct" style="color:{model_color(c["model"])}">{esc(model_label(c["model"]))}</div>'
                                    f'{route_html(c["route"])}', unsafe_allow_html=True)
                        st.markdown(f"""
| | |
|---|---|
| Verdict | {(summ.get('verdict') or '–').replace('_', ' ')} {ok(summ.get('verdict') == gt['verdict']) if gt['verdict'] else ''} |
| Model's route | {summ.get('recommended_route') or '–'} {ok(summ.get('recommended_route') == gt['route']) if gt['route'] != 'EXCEPTION' else ''} |
| Final route | {c['route']} {ok(c['route'] == gt['route'])} |
| Priority | {summ.get('priority', '–')} |
| Confidence | {pct(summ.get('confidence'))} |
| Model time | {lat:.1f}s |
| Guardrail flags | {flags} |
""")
                        with st.expander("Summary"):
                            st.write(summ.get("summary") or "No summary (see the case for details).")
                        st.button("Open full case", key=f"h2h-open-{c['case_id']}", on_click=open_case, args=(c["case_id"],),
                                  width="stretch")
            if rows:
                r = pd.DataFrame(rows)
                c1, c2 = st.columns(2)
                with c1:
                    with card("h2hlat"):
                        title("Model time per alert", "Sum of five agent calls")
                        show(style(go.Figure(go.Bar(x=[model_label(m) for m in r["model"]], y=r["latency"],
                                                    marker_color=[model_color(m) for m in r["model"]],
                                                    text=[f"{v:.1f}s" for v in r["latency"]], textposition="auto")), 280))
                with c2:
                    with card("h2hconf"):
                        title("Self-reported confidence", "Compare with whether the verdict was right")
                        fig = go.Figure(go.Bar(x=[model_label(m) for m in r["model"]], y=r["confidence"],
                                               marker_color=[model_color(m) for m in r["model"]],
                                               text=[pct(v) for v in r["confidence"]], textposition="auto"))
                        fig.update_yaxes(range=[0, 1.05], tickformat=".0%")
                        show(style(fig, 280))

    else:
        df = load_cases()
        live = df[df["route"].notna()] if not df.empty else df
        if live.empty:
            with card("nolive"):
                empty("No live cases yet", "Triage some alerts and this view compares how each model has behaved in use.")
            st.stop()
        g = live.groupby("model")
        tab = pd.DataFrame({"Cases": g.size(), "Median model time (s)": g["latency_s"].median().round(1),
                            "Mean confidence": g["confidence"].mean().round(2),
                            "Policy override rate": g["policy_override"].mean().round(2),
                            "Hallucinations per case": (g["hallucinations"].sum() / g.size()).round(2),
                            "Agent failures": g["agent_failures"].sum()})
        tab.index = [model_label(m) for m in tab.index]
        with card("livetab"):
            title("Live performance by model", "From every case triaged in this console (not ground-truth scored)")
            st.dataframe(tab, width="stretch")
        c1, c2 = st.columns(2)
        with c1:
            with card("liveroute"):
                title("Routes chosen per model")
                t = live.groupby(["model", "route"]).size().unstack(fill_value=0)
                fig = go.Figure([go.Bar(name=ROUTES[rt][0], x=[model_label(m) for m in t.index], y=t[rt], marker_color=ROUTES[rt][1])
                                 for rt in t.columns])
                fig.update_layout(barmode="stack")
                show(style(fig, 320))
        with c2:
            with card("livelat"):
                title("Model time distribution", "Per alert, in seconds")
                fig = go.Figure([go.Box(y=gr["latency_s"], name=model_label(m), marker_color=model_color(m), boxmean=True)
                                 for m, gr in live.groupby("model")])
                fig.update_layout(showlegend=False)
                show(style(fig, 320))

else:  # Audit and governance
    aud, err = api("GET", "/audit", params={"limit": 2000})
    pol, _ = api("GET", "/policy")
    ad = pd.DataFrame(aud or [])
    ev = ad["event"].value_counts() if not ad.empty else pd.Series(dtype=int)
    kpis([("Audit records", chain.get("rows_checked", 0), "append-only, hash-chained", C["accent"]),
          ("Chain integrity", "Intact" if chain.get("valid") else "Broken", "SHA-256 verified", C["a"] if chain.get("valid") else C["e"]),
          ("Human decisions", int(ev.get("human_decision", 0)), "approve or reject", C["h"]),
          ("RBAC denials", int(ev.get("rbac_denied", 0)), "role too low", C["e"]),
          ("Blocked executions", int(ev.get("execution_blocked", 0)), "no approval on record", C["e"]),
          ("Injections caught", int(ev.get("guardrail_injection_detected", 0)), "input scanner", C["x"])])
    c1, c2 = st.columns([1.3, 1])
    with c1:
        with card("events"):
            title("Audit events by type")
            top = ev.head(14)
            fig = go.Figure(go.Bar(x=top.values, y=[e.replace("_", " ") for e in top.index], orientation="h",
                                   marker_color=C["accent"], text=top.values, textposition="auto"))
            fig.update_yaxes(autorange="reversed")
            show(style(fig, 420))
    with c2:
        with card("bands"):
            title("Routing policy", "Enforced in code; models cannot change these thresholds")
            lo, hi = pol["auto_close_max_score"], pol["escalate_min_score"]
            fig = go.Figure()
            for name, base, width, color in [("Auto-close eligible", 0, lo, C["a"]), ("Analyst review", lo, hi - lo, C["h"]),
                                             ("Escalate", hi, 100 - hi, C["e"])]:
                fig.add_trace(go.Bar(x=[width], y=["Risk score"], base=base, orientation="h", name=name, marker_color=color,
                                     text=[name], textposition="inside", insidetextanchor="middle"))
            fig.update_layout(barmode="stack", showlegend=False)
            fig.update_xaxes(range=[0, 100], tickvals=[0, lo, hi, 100])
            show(style(fig, 150))
            st.markdown(f'<div class="flag good">Auto-close also needs a false-positive verdict with confidence of at least '
                        f'{pol["auto_close_min_confidence"]:.0%}. Injection, crown-jewel true positives and context gaps '
                        f'override the score.</div>', unsafe_allow_html=True)
            with st.expander("Full policy"):
                st.json(pol)
    with card("controls"):
        title("Governance controls", "Mapped to the risks they address")
        st.markdown("""
| Risk | Control | Enforced in |
|---|---|---|
| Prompt injection via log content | Pattern scanner, untrusted-evidence tagging, forced escalation | `guardrails.detect_injection`, `scoring.decide_route` |
| Hallucination | Schema validation, evidence-ID and IP/hash grounding, ATT&CK ID format check | `guardrails.validate_agent_output` |
| Unsafe autonomous action | Action allowlist; containment only after a recorded human approval | allowlist, `pipeline.execute` |
| Wrong prioritisation | Deterministic score and thresholds in code | `scoring.py`, `config.POLICY` |
| Confidential data exposure | E-mail and secret masking before any model call; synthetic data only | `guardrails.sanitize_alert` |
| Unauthorised approval | Role-based approval: L2 for review, SOC lead for escalations | `pipeline.record_decision` |
| Lack of accountability | Append-only, SHA-256 hash-chained audit log | `store.audit`, `/audit/verify` |
| Tool or model failure | Retries, timeouts, exception queue for incomplete context | `llm.chat`, `pipeline.run_step` |
""")
    with card("log"):
        a, b = st.columns([3, 1], vertical_alignment="bottom")
        cid = a.text_input("Filter the audit log by case ID")
        if b.button("Verify chain integrity", width="stretch"):
            st.cache_data.clear()
            v, _ = api("GET", "/audit/verify")
            if v and v["valid"]:
                st.success(f"Hash chain intact across {v['rows_checked']} records.")
            elif v:
                st.error(f"Tampering detected at record {v['broken_at_id']}.")
        if not ad.empty:
            view = ad[ad["case_id"].astype(str).str.contains(cid, regex=False)] if cid else ad
            st.dataframe(view[["id", "ts", "case_id", "event", "actor", "model", "prompt_version", "detail", "hash"]],
                         hide_index=True, width="stretch", height=380)

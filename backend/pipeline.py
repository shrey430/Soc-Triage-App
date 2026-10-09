"""Case lifecycle shared by BOTH engines:
  * n8n calls these functions step by step through the REST API (primary engine)
  * run_pipeline() runs the same steps in-process (fallback engine + benchmark)
Every step is logged to the tamper-evident audit trail."""
import threading
import time
import uuid

import requests

from . import agents, guardrails, scoring, store, tools
from .config import N8N_TIMEOUT, POLICY, PROMPT_VERSION

STEPS = ["related_alerts", "correlation_agent", "ti_lookup", "threat_intel_agent", "asset_lookup",
         "asset_context_agent", "risk_score", "risk_agent", "summary_agent", "route"]
PENDING = ("PENDING_APPROVAL", "PENDING_ESCALATION", "EXCEPTION_QUEUE")
FINAL = ("AUTO_CLOSED", "CLOSED_REJECTED", "RESOLVED", "RESOLVED_CONTAINED")
_exec_lock = threading.Lock()


def new_case_id():
    return f"CASE-{time.strftime('%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"


def _load(case_id):
    case = store.get_case(case_id)
    if not case:
        raise KeyError(case_id)
    return case


# ------------------------------------------------------------------ start
def start_case(alert, model, case_id=None, source="api", prompt_version=PROMPT_VERSION, backend_url=None):
    case_id = case_id or new_case_id()
    errors = guardrails.validate_alert(alert)
    raw = alert if isinstance(alert, dict) else {"raw_input": str(alert)}
    sanitized, redactions = guardrails.sanitize_alert(raw)
    injection = guardrails.detect_injection(sanitized)
    state = {
        "case_id": case_id, "model": model, "prompt_version": prompt_version, "alert": sanitized,
        "validation": {"valid": not errors, "errors": errors, "redactions": redactions,
                       "injection_matches": injection},
        "evidence": [{"id": "EV-ALERT", "type": "alert", "data": sanitized}],
        "tools": {}, "agents": {}, "score": None, "route": None, "gaps": [], "steps": [],
        "required_role": None, "decision": None, "actions_executed": [], "notifications": [],
        "ctx": {"case_id": case_id, "model": model, "backend_url": backend_url},
    }
    store.create_case(case_id, source, model, state)
    store.audit(case_id, "case_created", actor=source, model=model, prompt_version=prompt_version,
                detail={"alert_id": sanitized.get("alert_id"), "rule": sanitized.get("rule_name")})
    store.audit(case_id, "guardrail_input_validation", detail=state["validation"])
    if injection:
        store.audit(case_id, "guardrail_injection_detected", detail=injection)
    return {"case_id": case_id, "valid": not errors, "errors": errors,
            "injection_matches": injection, "redactions": redactions, "ctx": state["ctx"]}


# ------------------------------------------------------------------ steps
def _agent(state, name, model):
    prior = {k: v["output"] for k, v in state["agents"].items() if v.get("ok")}
    res = agents.run_agent(name, model, state["evidence"], prior, state.get("prompt_version", "v3"))
    state["agents"][name] = res
    if not res["ok"]:
        state["gaps"].append(f"{name} agent failed: {res['error'] or res['errors']}")
    store.audit(state["case_id"], f"agent_{name}", actor=f"agent:{name}", model=model,
                prompt_version=res["prompt_version"],
                detail={k: res[k] for k in ("ok", "latency_s", "attempts", "errors", "hallucinations",
                                            "blocked", "error", "output")})
    return {k: res[k] for k in ("ok", "output", "latency_s", "hallucinations", "blocked", "error")}


def _related(state, model):
    rel = tools.related_alerts(state["alert"])
    state["tools"]["related"] = rel
    for i, r in enumerate(rel, 1):
        state["evidence"].append({"id": f"EV-REL-{i}", "type": "related_alert", "data": r})
    store.audit(state["case_id"], "tool_siem_related_alerts", actor="tool:siem", detail={"count": len(rel)})
    return {"related_count": len(rel)}


def _ti(state, model):
    res = tools.ti_lookup(tools.extract_indicators(state["alert"]))
    state["tools"]["ti"] = res
    for i, r in enumerate(res, 1):
        state["evidence"].append({"id": f"EV-TI-{i}", "type": "threat_intel", "data": r})
        if r["verdict"] == "unavailable":
            state["gaps"].append(f"Threat intel unavailable for {r['indicator']}")
    store.audit(state["case_id"], "tool_threat_intel_lookup", actor="tool:threat-intel", detail=res)
    return {"lookups": res}


def _asset(state, model):
    host = state["alert"].get("host")
    asset = tools.lookup_asset(host)
    state["tools"]["asset"] = asset
    state["evidence"].append({"id": "EV-ASSET", "type": "asset",
                              "data": asset or {"host": host, "found": False}})
    if not asset:
        state["gaps"].append(f"Asset '{host}' not found in CMDB")
    store.audit(state["case_id"], "tool_cmdb_lookup", actor="tool:cmdb", detail=asset or {"host": host, "found": False})
    return {"asset": asset}


def _score(state, model):
    sc = scoring.compute_risk_score(state["alert"], state["tools"].get("asset"),
                                    state["tools"].get("ti", []), state["tools"].get("related", []))
    state["score"] = sc
    state["evidence"].append({"id": "EV-SCORE", "type": "risk_score", "data": sc})
    store.audit(state["case_id"], "risk_score_computed", actor="policy-engine", detail=sc)
    return sc


def _route(state, model):
    r = scoring.decide_route(state)
    state["route"] = r
    state["required_role"] = r["required_role"]
    store.audit(state["case_id"], "routing_decision", actor="policy-engine", detail=r)
    return r


STEP_FUNCS = {
    "related_alerts": _related,
    "correlation_agent": lambda s, m: _agent(s, "correlation", m),
    "ti_lookup": _ti,
    "threat_intel_agent": lambda s, m: _agent(s, "threat_intel", m),
    "asset_lookup": _asset,
    "asset_context_agent": lambda s, m: _agent(s, "asset_context", m),
    "risk_score": _score,
    "risk_agent": lambda s, m: _agent(s, "risk", m),
    "summary_agent": lambda s, m: _agent(s, "summary", m),
    "route": _route,
}


def run_step(case_id, step, model=None):
    if step not in STEP_FUNCS:
        raise ValueError(f"Unknown step '{step}'")
    case = _load(case_id)
    state = case["state"]
    model = model or state["model"]
    t0 = time.time()
    try:
        result = STEP_FUNCS[step](state, model)
        ok = not (isinstance(result, dict) and result.get("ok") is False)
    except Exception as e:  # exception handling: never crash the workflow
        result, ok = {"error": str(e)}, False
        state["gaps"].append(f"Step {step} failed: {e}")
        store.audit(case_id, "step_error", detail={"step": step, "error": str(e)})
    state["steps"].append({"step": step, "seconds": round(time.time() - t0, 3), "ok": ok})
    if step == "route":
        case["route"] = state["route"]["route"]
    store.save_case(case)
    return {"case_id": case_id, "step": step, "ok": ok, "result": result, "ctx": state.get("ctx")}


# ------------------------------------------------------------------ branches
def apply_branch(case_id, branch, resume_url=None):
    case = _load(case_id)
    st = case["state"]
    if st.get("route") is None:
        st["route"] = scoring.decide_route(st)
        st["required_role"] = st["route"]["required_role"]
        case["route"] = st["route"]["route"]
        store.audit(case_id, "routing_decision", actor="policy-engine", detail=st["route"])
    alert_id = st["alert"].get("alert_id")
    if branch == "auto_close":
        res = tools.execute_action("close_alert", alert_id, case_id, "policy-engine (autonomous)")
        st["actions_executed"].append(res)
        case["status"] = "AUTO_CLOSED"
        store.audit(case_id, "auto_closed", actor="policy-engine", detail=res)
    elif branch == "escalate":
        n = tools.notify("Pager: IR lead on call", f"{case_id} escalated: {st['route']['reasons']}")
        st["notifications"].append(n)
        st["required_role"] = "SOC_LEAD"
        case["status"] = "PENDING_ESCALATION"
        store.audit(case_id, "escalated_to_ir_lead", actor="policy-engine", detail=n)
    elif branch == "await_approval":
        if case["status"] != "PENDING_ESCALATION":
            case["status"] = "PENDING_APPROVAL"
            st["required_role"] = st.get("required_role") or "L2_ANALYST"
        case["resume_url"] = resume_url
        store.audit(case_id, "awaiting_human_approval", actor="workflow",
                    detail={"required_role": st["required_role"], "n8n_wait_registered": bool(resume_url)})
    elif branch == "exception":
        st["required_role"] = "L2_ANALYST"
        n = tools.notify("SOC exception queue", f"{case_id}: {st['route']['reasons']}")
        st["notifications"].append(n)
        case["status"] = "EXCEPTION_QUEUE"
        store.audit(case_id, "exception_queued", actor="policy-engine", detail=st["route"]["reasons"])
    else:
        raise ValueError(f"Unknown branch '{branch}'")
    store.save_case(case)
    return {"case_id": case_id, "status": case["status"], "route": case["route"], "ctx": st.get("ctx")}


# ------------------------------------------------------------------ HITL
def record_decision(case_id, decision, approver, role, approved_actions=None, comment=""):
    case = _load(case_id)
    st = case["state"]
    roles = POLICY["roles"]
    if case["status"] not in PENDING:
        raise ValueError(f"Case is {case['status']}; no decision is pending")
    if decision not in ("approve", "reject", "escalate"):
        raise ValueError("decision must be approve, reject or escalate")
    if role not in roles:
        raise ValueError(f"Unknown role {role}")
    if not (approver or "").strip():
        raise ValueError("Approver name is required for the audit trail")
    actor = f"{approver} ({role})"

    if decision == "escalate":
        if case["status"] == "PENDING_ESCALATION":
            raise ValueError("Case is already escalated")
        st["required_role"] = "SOC_LEAD"
        case["status"] = "PENDING_ESCALATION"
        st["notifications"].append(tools.notify("Pager: IR lead on call", f"{case_id} escalated by {actor}"))
        store.audit(case_id, "human_escalated", actor=actor, detail={"comment": comment})
        store.save_case(case)
        return {"case_id": case_id, "status": case["status"]}

    required = st.get("required_role") or "L2_ANALYST"
    if roles[role] < roles[required]:
        store.audit(case_id, "rbac_denied", actor=actor, detail={"required_role": required, "decision": decision})
        raise PermissionError(f"{role} cannot {decision} this case; it requires {required}")

    recs = ((st["agents"].get("summary") or {}).get("output") or {}).get("recommended_actions") or []
    chosen = []
    if decision == "approve":
        for i in approved_actions or []:
            if not 0 <= int(i) < len(recs):
                raise ValueError(f"Action index {i} does not exist")
            chosen.append(recs[int(i)])
    st["decision"] = {"decision": decision, "approver": approver, "role": role,
                      "approved_actions": chosen, "comment": comment, "ts": store.now()}
    case["status"] = "DECISION_RECORDED"
    store.audit(case_id, "human_decision", actor=actor, detail=st["decision"])
    store.save_case(case)

    resume_url = case.get("resume_url")
    if resume_url:
        try:
            r = requests.post(resume_url, json={"case_id": case_id, "decision": decision, "approver": approver, "ctx": st.get("ctx")},
                              timeout=N8N_TIMEOUT)
            r.raise_for_status()
            store.audit(case_id, "n8n_workflow_resumed", actor="workflow")
            return {"case_id": case_id, "status": _load(case_id)["status"], "resumed": "n8n"}
        except requests.Timeout:
            store.audit(case_id, "n8n_workflow_resumed", actor="workflow", detail="resume call timed out; n8n continues")
            return {"case_id": case_id, "status": _load(case_id)["status"], "resumed": "n8n"}
        except requests.RequestException as e:
            store.audit(case_id, "n8n_resume_failed", actor="workflow", detail=str(e))
    return execute(case_id, actor="backend")


def execute(case_id, actor="api"):
    with _exec_lock:
        case = _load(case_id)
        st = case["state"]
        if case["status"] in FINAL:
            return {"case_id": case_id, "status": case["status"], "note": "already finalised"}
        d = st.get("decision")
        if not d or d["decision"] not in ("approve", "reject"):
            store.audit(case_id, "execution_blocked", actor=actor, detail="No recorded human decision")
            raise PermissionError("Execution blocked: no recorded human decision (HITL guardrail)")
        if d["decision"] == "reject":
            case["status"] = "CLOSED_REJECTED"
            store.audit(case_id, "closed_rejected", actor=actor, detail=d)
        else:
            results = [tools.execute_action(a["action"], a["target"], case_id, f"{d['approver']} ({d['role']})")
                       for a in d["approved_actions"]]
            st["actions_executed"].extend(results)
            contained = any(a.get("high_impact") for a in d["approved_actions"])
            case["status"] = "RESOLVED_CONTAINED" if contained else "RESOLVED"
            for r in results:
                store.audit(case_id, "response_action_executed", actor=f"{actor} on behalf of {d['approver']}", detail=r)
        store.save_case(case)
        return {"case_id": case_id, "status": case["status"], "actions_executed": st["actions_executed"]}


# ------------------------------------------------------------------ in-process engine
def run_pipeline(alert, model, case_id=None, source="python-engine", prompt_version=PROMPT_VERSION):
    info = start_case(alert, model, case_id, source, prompt_version)
    cid = info["case_id"]
    if info["valid"]:
        for step in STEPS:
            run_step(cid, step, model)
        route = _load(cid)["state"]["route"]["route"]
    else:
        route = "EXCEPTION"
    if route == "AUTO_CLOSE":
        apply_branch(cid, "auto_close")
    elif route == "ANALYST_REVIEW":
        apply_branch(cid, "await_approval")
    elif route == "ESCALATE":
        apply_branch(cid, "escalate")
        apply_branch(cid, "await_approval")
    else:
        apply_branch(cid, "exception")
    return _load(cid)

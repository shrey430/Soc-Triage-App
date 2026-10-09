"""Deterministic guardrails. These run in code, so they hold even when a model
misbehaves:
  * input validation of alerts
  * PII / secret masking before anything reaches a model
  * prompt-injection detection on untrusted log content
  * agent-output schema validation (structured-output compliance)
  * grounding / hallucination checks (evidence IDs, IPs, hashes, ATT&CK IDs)
  * action allowlisting
"""
import copy
import json
import re
from datetime import datetime

from .config import POLICY

REQUIRED_ALERT_FIELDS = ["alert_id", "timestamp", "source", "rule_name", "severity"]
MAX_FIELD_CHARS = 3000

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"disregard\s+(all\s+|the\s+|any\s+)?(previous|prior|above|system)",
    r"(note|message|instruction)s?\s+to\s+(the\s+)?(ai|assistant|llm|model|agent)",
    r"you\s+are\s+now\s+(a|an|the)\s+",
    r"(reveal|print|show|repeat)\s+(your\s+|the\s+)?(system\s+prompt|instructions)",
    r"classify\s+(this|it|the\s+alert)\s+as\s+(a\s+)?(benign|false\s+positive|safe|harmless)",
    r"do\s+not\s+(escalate|alert|report)",
    r"mark\s+(this|it)\s+as\s+(benign|safe|resolved|closed)",
]
_INJ = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*[^\s,;|']+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---------------------------------------------------------------- input side
def validate_alert(alert):
    if not isinstance(alert, dict):
        return ["Alert is not a JSON object"]
    errors = []
    for field in REQUIRED_ALERT_FIELDS:
        v = alert.get(field)
        if v is None or (isinstance(v, str) and not v.strip()):
            errors.append(f"Missing required field '{field}'")
    sev = alert.get("severity")
    if sev is not None:
        try:
            if not 1 <= int(sev) <= 5:
                errors.append("Severity must be between 1 and 5")
        except (TypeError, ValueError):
            errors.append("Severity is not a number")
    ts = alert.get("timestamp")
    if ts:
        try:
            datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            errors.append("Timestamp is not ISO-8601")
    if not alert.get("host") and not alert.get("user"):
        errors.append("Alert must identify a host or a user")
    return errors


def _walk(obj, fn):
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, fn) for v in obj]
    if isinstance(obj, str):
        return fn(obj)
    return obj


def _strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def sanitize_alert(alert):
    """Mask e-mails and secrets, truncate oversized fields. Returns (alert, redactions)."""
    counter = {"emails": 0, "secrets": 0, "truncated": 0}

    def fix(s):
        s, n = EMAIL_RE.subn("[EMAIL_REDACTED]", s)
        counter["emails"] += n
        s, n = SECRET_RE.subn(lambda m: f"{m.group(1)}=[SECRET_REDACTED]", s)
        counter["secrets"] += n
        if len(s) > MAX_FIELD_CHARS:
            counter["truncated"] += 1
            s = s[:MAX_FIELD_CHARS] + " …[TRUNCATED]"
        return s

    return _walk(copy.deepcopy(alert), fix), counter


def detect_injection(obj):
    hits = []
    for s in _strings(obj):
        for rx in _INJ:
            m = rx.search(s)
            if m:
                hits.append(s[max(0, m.start() - 20): m.end() + 40].strip())
    return sorted(set(hits))


# --------------------------------------------------------------- output side
AGENT_SCHEMAS = {
    "correlation": {"related_alert_ids": list, "attack_pattern": str, "kill_chain_stage": str,
                    "mitre_techniques": list, "correlation_strength": str, "evidence_ids": list,
                    "injection_suspected": bool},
    "threat_intel": {"overall_verdict": str, "indicator_assessments": list, "confidence": float,
                     "evidence_ids": list, "injection_suspected": bool},
    "asset_context": {"business_impact": str, "impact_rationale": str, "blast_radius": str,
                      "data_sensitivity": str, "evidence_ids": list},
    "risk": {"verdict": str, "confidence": float, "rationale": str, "score_agreement": str,
             "evidence_ids": list, "injection_suspected": bool},
    "summary": {"title": str, "verdict": str, "priority": str, "confidence": float, "summary": str,
                "mitre_techniques": list, "recommended_actions": list, "recommended_route": str,
                "evidence_ids": list, "injection_suspected": bool, "open_questions": list},
}

ENUMS = {
    "kill_chain_stage": ["reconnaissance", "initial_access", "execution", "persistence",
                         "privilege_escalation", "defense_evasion", "credential_access", "discovery",
                         "lateral_movement", "command_and_control", "exfiltration", "impact",
                         "benign_activity", "unknown"],
    "correlation_strength": ["none", "weak", "moderate", "strong"],
    "overall_verdict": ["malicious", "suspicious", "clean", "unknown"],
    "business_impact": ["low", "medium", "high", "critical", "unknown"],
    "data_sensitivity": ["low", "medium", "high", "unknown"],
    "verdict": ["true_positive", "false_positive", "needs_investigation"],
    "score_agreement": ["agree", "too_high", "too_low"],
    "priority": ["P1", "P2", "P3", "P4"],
    "recommended_route": ["AUTO_CLOSE", "ANALYST_REVIEW", "ESCALATE"],
}
_UPPER_ENUMS = {"priority", "recommended_route"}


def _norm_enum(field, value):
    v = str(value).strip().replace("-", "_").replace(" ", "_")
    return v.upper() if field in _UPPER_ENUMS else v.lower()


def _grounding(out, evidence):
    """Flag IPs / hashes in the output that never appear in the evidence."""
    ev_text = json.dumps(evidence, default=str).lower()
    out_text = json.dumps(out, default=str)
    flags = []
    for ip in set(IPV4_RE.findall(out_text)):
        if ip.lower() not in ev_text:
            flags.append(f"ungrounded IP {ip}")
    for h in set(SHA256_RE.findall(out_text)):
        if h.lower() not in ev_text:
            flags.append(f"ungrounded hash {h[:12]}…")
    return flags


def validate_agent_output(agent, obj, evidence):
    """Returns dict(errors, hallucinations, blocked, cleaned). Errors trigger a
    retry; hallucinations and blocked actions are removed and logged."""
    res = {"errors": [], "hallucinations": [], "blocked": [], "cleaned": None}
    if not isinstance(obj, dict):
        res["errors"].append("Output is not a JSON object")
        return res
    out = copy.deepcopy(obj)
    for key, typ in AGENT_SCHEMAS[agent].items():
        if key not in out or out[key] is None:
            res["errors"].append(f"missing field '{key}'")
            continue
        v = out[key]
        if typ is float:
            try:
                v = float(v)
            except (TypeError, ValueError):
                res["errors"].append(f"'{key}' must be a number 0-1")
                continue
            if 1 < v <= 100:
                v = v / 100
            if not 0 <= v <= 1:
                res["errors"].append(f"'{key}' must be between 0 and 1")
            out[key] = v
        elif typ is bool:
            if isinstance(v, str) and v.strip().lower() in ("true", "false"):
                v = v.strip().lower() == "true"
            if not isinstance(v, bool):
                res["errors"].append(f"'{key}' must be true/false")
            out[key] = v
        elif typ is list:
            if isinstance(v, str):
                out[key] = [v] if v.strip() else []
            elif not isinstance(v, list):
                res["errors"].append(f"'{key}' must be a list")
        elif typ is str and not isinstance(v, str):
            out[key] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        if key in ENUMS and isinstance(out.get(key), str):
            out[key] = _norm_enum(key, out[key])
            if out[key] not in ENUMS[key]:
                res["errors"].append(f"'{key}'='{out[key]}' not in {ENUMS[key]}")
    if res["errors"]:
        return res

    valid_ids = {e["id"] for e in evidence}
    kept = []
    for eid in out.get("evidence_ids", []):
        (kept.append(str(eid)) if str(eid) in valid_ids
         else res["hallucinations"].append(f"unknown evidence id '{eid}'"))
    out["evidence_ids"] = kept
    if agent in ("risk", "summary") and not kept:
        res["errors"].append("must cite at least one valid evidence id")
        return res

    if "mitre_techniques" in out:
        techs = []
        for t in out["mitre_techniques"]:
            tid = (t.get("id") if isinstance(t, dict) else t) or ""
            tid = str(tid).strip().upper()
            if TECH_RE.match(tid):
                techs.append({"id": tid, "name": str(t.get("name", "")) if isinstance(t, dict) else ""})
            else:
                res["hallucinations"].append(f"invalid ATT&CK id '{tid}'")
        out["mitre_techniques"] = techs

    if agent == "correlation":
        known = {str(e["data"].get("alert_id")) for e in evidence
                 if isinstance(e.get("data"), dict) and e["data"].get("alert_id")}
        rel = []
        for a in out["related_alert_ids"]:
            (rel.append(str(a)) if str(a) in known
             else res["hallucinations"].append(f"unknown alert id '{a}'"))
        out["related_alert_ids"] = rel

    if agent == "summary":
        acts = []
        for a in out["recommended_actions"]:
            if not isinstance(a, dict):
                a = {"action": str(a)}
            name = str(a.get("action", "")).strip().lower().replace(" ", "_")
            if name not in POLICY["allowed_actions"]:
                res["blocked"].append(f"action '{name}' is not on the allowlist")
                continue
            acts.append({"action": name, "target": str(a.get("target", "")),
                         "justification": str(a.get("justification", "")),
                         "high_impact": name in POLICY["high_impact_actions"]})
        out["recommended_actions"] = acts

    res["hallucinations"] += _grounding(out, evidence)
    res["cleaned"] = out
    return res


_JSON_TYPES = {list: "array", str: "string", float: "number", bool: "boolean"}


def json_schema_for(agent):
    """JSON Schema for an agent's output, used for provider-side structured output
    (constrained decoding). Built from AGENT_SCHEMAS so the two never drift."""
    props = {}
    for key, typ in AGENT_SCHEMAS[agent].items():
        prop = {"type": _JSON_TYPES[typ]}
        if key in ENUMS:
            prop["enum"] = ENUMS[key]
        if typ is list:
            prop["items"] = {"type": "object"} if key in ("mitre_techniques", "recommended_actions",
                                                           "indicator_assessments") else {"type": "string"}
        props[key] = prop
    return {"type": "json_schema", "json_schema": {"name": f"{agent}_output", "strict": False,
            "schema": {"type": "object", "properties": props, "required": list(props)}}}

"""Runs one specialised agent: builds the STOIC prompt, calls the model through
the gateway, validates the output against its schema, retries once with the
validation errors, and returns a fully traceable result."""
import json
import time

from . import guardrails, llm, prompts

AGENTS = ["correlation", "threat_intel", "asset_context", "risk", "summary"]


def _messages(agent, evidence, prior, version):
    ids = ", ".join(e["id"] for e in evidence)
    user = ("<untrusted_evidence>\n" + json.dumps(evidence, indent=1, default=str) +
            "\n</untrusted_evidence>\n")
    if prior:
        user += ("\n<prior_agent_findings>\n" + json.dumps(prior, indent=1, default=str) +
                 "\n</prior_agent_findings>\n")
    user += f"\nValid evidence IDs: {ids}\nReturn the JSON object now."
    return [{"role": "system", "content": prompts.get_prompt(agent, version)},
            {"role": "user", "content": user}]


def run_agent(agent, model_key, evidence, prior=None, version="v3"):
    version = version if agent == "summary" else "v3"
    base = {"agent": agent, "model": model_key, "prompt_version": version, "ok": False,
            "output": None, "raw": "", "latency_s": 0.0, "attempts": 0, "first_try_valid": False,
            "errors": [], "hallucinations": [], "blocked": [], "error": None}

    if llm.is_mock(model_key):
        t0 = time.time()
        obj = mock_respond(agent, evidence)
        v = guardrails.validate_agent_output(agent, obj, evidence)
        base.update(ok=not v["errors"], output=v["cleaned"], raw=json.dumps(obj), attempts=1,
                    first_try_valid=not v["errors"], errors=v["errors"],
                    hallucinations=v["hallucinations"], blocked=v["blocked"],
                    latency_s=round(time.time() - t0, 3))
        return base

    messages = _messages(agent, evidence, prior, version)
    for attempt in range(2):
        base["attempts"] = attempt + 1
        try:
            text, latency = llm.chat(model_key, messages, schema=guardrails.json_schema_for(agent))
        except llm.LLMError as e:
            base["error"] = str(e)
            return base
        base["latency_s"] = round(base["latency_s"] + latency, 3)
        base["raw"] = text
        try:
            obj = llm.extract_json(text)
            v = guardrails.validate_agent_output(agent, obj, evidence)
            errors = v["errors"]
        except ValueError as e:
            v, errors = None, [f"not valid JSON ({e})"]
        if not errors:
            base.update(ok=True, output=v["cleaned"], first_try_valid=(attempt == 0),
                        hallucinations=v["hallucinations"], blocked=v["blocked"], errors=[])
            return base
        base["errors"] = errors
        messages = messages + [
            {"role": "assistant", "content": text[:4000]},
            {"role": "user", "content": "Your previous reply failed validation: " + "; ".join(errors) +
             ". Reply with ONLY a corrected JSON object that matches the schema."}]
    base["error"] = "Output failed schema validation after one retry"
    return base


# --------------------------------------------------------------------------
# Offline mock: a transparent rule-based stand-in so the whole workflow can be
# demonstrated and tested without API keys. It is NOT one of the compared models.
_KEYWORDS = {
    "encrypt": ("T1486", "Data Encrypted for Impact"),
    "delete shadows": ("T1490", "Inhibit System Recovery"),
    "powershell": ("T1059.001", "PowerShell"),
    "-enc": ("T1027", "Obfuscated Files or Information"),
    "macro": ("T1566.001", "Spearphishing Attachment"),
    "impossible travel": ("T1078", "Valid Accounts"),
    "beacon": ("T1071", "Application Layer Protocol"),
    "rare external ip": ("T1071", "Application Layer Protocol"),
}


def mock_respond(agent, evidence):
    ev = {e["id"]: e for e in evidence}
    alert = ev.get("EV-ALERT", {}).get("data", {}) or {}
    rel = [e for e in evidence if e["id"].startswith("EV-REL")]
    ti = [e for e in evidence if e["id"].startswith("EV-TI")]
    asset = (ev.get("EV-ASSET") or {}).get("data") or {}
    text = json.dumps([alert] + [r["data"] for r in rel]).lower()
    injection = bool(guardrails.detect_injection(alert))
    verdicts = [t["data"].get("verdict") for t in ti]
    worst = ("malicious" if "malicious" in verdicts else "suspicious" if "suspicious" in verdicts
             else "unknown" if any(v in ("unknown", "unavailable") for v in verdicts) or not verdicts
             else "clean")
    techs, seen = [], set()
    for k, (tid, name) in _KEYWORDS.items():
        if k in text and tid not in seen:
            seen.add(tid)
            techs.append({"id": tid, "name": name})
    sev = int(alert.get("severity", 3) or 3)
    crit = int(asset.get("criticality", 3)) if asset.get("found") else 3
    if worst == "malicious" or injection or (sev >= 4 and rel):
        verdict, conf = "true_positive", 0.9
    elif worst in ("clean", "unknown") and sev <= 2 and all(v in ("clean", "internal") for v in verdicts):
        verdict, conf = "false_positive", 0.9
    else:
        verdict, conf = "needs_investigation", 0.6 if asset.get("found") else 0.4
    ids = [e["id"] for e in evidence]
    host = alert.get("host", "")

    if agent == "correlation":
        return {"related_alert_ids": [r["data"]["alert_id"] for r in rel],
                "attack_pattern": "Related alerts on the same host/user" if rel else "Isolated alert",
                "kill_chain_stage": "impact" if "T1486" in seen else ("execution" if seen else "benign_activity"),
                "mitre_techniques": techs,
                "correlation_strength": "strong" if len(rel) >= 3 else "moderate" if rel else "none",
                "evidence_ids": [i for i in ids if i.startswith(("EV-ALERT", "EV-REL"))],
                "injection_suspected": injection}
    if agent == "threat_intel":
        return {"overall_verdict": worst,
                "indicator_assessments": [{"indicator": t["data"].get("indicator"), "verdict": t["data"].get("verdict"),
                                           "reason": ", ".join(t["data"].get("tags", [])) or t["data"].get("source", "")}
                                          for t in ti],
                "confidence": 0.5 if worst == "unknown" else 0.85,
                "evidence_ids": [t["id"] for t in ti] or ["EV-ALERT"], "injection_suspected": injection}
    if agent == "asset_context":
        if not asset.get("found"):
            return {"business_impact": "unknown", "impact_rationale": "Asset not in CMDB (context gap).",
                    "blast_radius": "Unknown", "data_sensitivity": "unknown", "evidence_ids": ["EV-ASSET"]}
        imp = {1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical"}[crit]
        return {"business_impact": imp, "impact_rationale": f"{asset.get('role')} with criticality {crit}.",
                "blast_radius": "Crown-jewel system" if asset.get("crown_jewel") else "Single endpoint",
                "data_sensitivity": "high" if "restricted" in str(asset.get("data_classification")) else "medium" if crit >= 3 else "low",
                "evidence_ids": ["EV-ASSET"]}
    if agent == "risk":
        return {"verdict": verdict, "confidence": conf, "rationale": f"Rule-based mock: TI={worst}, related={len(rel)}.",
                "score_agreement": "agree", "evidence_ids": ["EV-SCORE", "EV-ALERT"], "injection_suspected": injection}
    # summary
    if verdict == "true_positive":
        prio = "P1" if (crit >= 4 or worst == "malicious") else "P2"
        route = "ESCALATE"
        actions = [{"action": "isolate_host", "target": host, "justification": "Contain likely compromise"}]
        for t in ti:
            if t["data"].get("verdict") in ("malicious", "suspicious"):
                kind = "block_domain" if t["data"].get("type") == "domain" else "block_ip" if t["data"].get("type") == "ip" else "quarantine_file"
                actions.append({"action": kind, "target": t["data"].get("indicator"), "justification": "Known-bad indicator"})
        actions.append({"action": "create_ticket", "target": host, "justification": "Track incident"})
    elif verdict == "false_positive":
        prio, route = "P4", "AUTO_CLOSE"
        actions = [{"action": "close_alert", "target": alert.get("alert_id", ""), "justification": "Benign activity"}]
    else:
        prio, route = "P3", "ANALYST_REVIEW"
        actions = [{"action": "create_ticket", "target": host or alert.get("user", ""), "justification": "Needs investigation"},
                   {"action": "monitor", "target": host or alert.get("user", ""), "justification": "Watch for follow-on activity"}]
    return {"title": alert.get("rule_name", "Security alert"), "verdict": verdict, "priority": prio,
            "confidence": conf, "summary": f"Mock summary for {alert.get('alert_id')}: verdict {verdict} (TI {worst}).",
            "mitre_techniques": techs, "recommended_actions": actions, "recommended_route": route,
            "evidence_ids": ids[:4], "injection_suspected": injection,
            "open_questions": [] if verdict != "needs_investigation" else ["Confirm activity with the user or asset owner"]}

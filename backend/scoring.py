"""Deterministic risk scoring and routing policy. The LLMs explain and judge;
this code decides the route, so thresholds are auditable and cannot be talked
out of by a model or by injected text."""
from .config import POLICY


def compute_risk_score(alert, asset, ti_results, related):
    w = POLICY["score_weights"]
    assumptions = []
    sev = int(alert.get("severity", 3) or 3)
    if asset:
        crit = int(asset["criticality"])
    else:
        crit = 3
        assumptions.append("Asset not in CMDB: criticality assumed 3 (medium)")
    verdicts = [t.get("verdict") for t in ti_results]
    if "malicious" in verdicts:
        ti_pts, ti_label = w["ti_malicious"], "malicious"
    elif "suspicious" in verdicts:
        ti_pts, ti_label = w["ti_suspicious"], "suspicious"
    else:
        ti_pts, ti_label = 0, "none"
    if "unavailable" in verdicts:
        assumptions.append("Threat intel unavailable for at least one indicator: scored as 0")
    n_rel = min(len(related), w["max_related"])
    components = {
        "severity": {"value": sev, "points": sev * w["severity"]},
        "asset_criticality": {"value": crit, "points": crit * w["criticality"]},
        "threat_intel": {"value": ti_label, "points": ti_pts},
        "related_alerts": {"value": len(related), "points": n_rel * w["per_related_alert"]},
    }
    score = min(100, sum(c["points"] for c in components.values()))
    return {"score": score, "components": components, "assumptions": assumptions,
            "formula": "severity x8 + criticality x6 + TI (malicious 20 / suspicious 10) + related alerts x3 (max 5), capped at 100"}


def decide_route(state):
    p = POLICY
    v = state["validation"]
    if not v["valid"]:
        return _r("EXCEPTION", ["Input validation failed: " + "; ".join(v["errors"])], None)

    summary = (state["agents"].get("summary") or {}).get("output") or {}
    verdict = summary.get("verdict")
    conf = float(summary.get("confidence") or 0)
    model_route = summary.get("recommended_route")
    score = (state.get("score") or {}).get("score", 0)
    asset = state["tools"].get("asset") or {}
    model_injection = any((a.get("output") or {}).get("injection_suspected") for a in state["agents"].values())

    if v["injection_matches"] or model_injection:
        src = "input scanner" if v["injection_matches"] else "an agent"
        return _r("ESCALATE", [f"Prompt-injection content detected by {src}: untrusted AI output, human lead must review"], model_route)
    if score >= p["escalate_min_score"]:
        return _r("ESCALATE", [f"Risk score {score} >= escalation threshold {p['escalate_min_score']}"], model_route)
    if asset.get("crown_jewel") and verdict == "true_positive":
        return _r("ESCALATE", ["Likely true positive on a crown-jewel asset"], model_route)
    if state.get("gaps"):
        return _r("EXCEPTION", ["Incomplete context, a human must triage: " + "; ".join(state["gaps"])], model_route)
    if score < p["auto_close_max_score"] and verdict == "false_positive" and conf >= p["auto_close_min_confidence"]:
        return _r("AUTO_CLOSE", [f"Score {score} < {p['auto_close_max_score']}, verdict false_positive, "
                                 f"confidence {conf:.2f} >= {p['auto_close_min_confidence']}"], model_route)
    reasons = [f"Score {score} is in the review band ({p['auto_close_max_score']}-{p['escalate_min_score'] - 1})"
               if p["auto_close_max_score"] <= score < p["escalate_min_score"] else f"Score {score}"]
    if verdict != "false_positive":
        reasons.append(f"Verdict is {verdict}")
    if conf < p["auto_close_min_confidence"]:
        reasons.append(f"Confidence {conf:.2f} is below the auto-close threshold")
    return _r("ANALYST_REVIEW", reasons, model_route)


def _r(route, reasons, model_route):
    override = bool(model_route) and model_route != route
    if override:
        reasons = reasons + [f"Policy overrode the model's recommendation ({model_route})"]
    return {"route": route, "reasons": reasons, "model_route": model_route, "policy_override": override,
            "required_role": POLICY["route_required_role"][route]}

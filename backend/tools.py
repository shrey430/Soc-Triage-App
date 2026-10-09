"""Simulated SOC tool integrations (SIEM search, threat intelligence, CMDB, EDR,
paging). Each function mirrors the shape of a real API so it can be swapped for
a live integration (e.g. AbuseIPDB, VirusTotal, ServiceNow CMDB) later."""
import csv
import ipaddress
import json
import time
import uuid

from .config import DATA_DIR

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _load_json(name):
    with open(DATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def load_cmdb():
    with open(DATA_DIR / "cmdb.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["criticality"] = int(r["criticality"])
        r["crown_jewel"] = r["crown_jewel"].strip().lower() == "true"
    return {r["host"].lower(): r for r in rows}


def lookup_asset(host):
    rec = load_cmdb().get(str(host or "").lower())
    return {**rec, "found": True} if rec else None


def _is_internal(value):
    try:
        ip = ipaddress.ip_address(value)
        return any(ip in n for n in _PRIVATE_NETS)
    except ValueError:
        return False


def extract_indicators(alert):
    out, seen = [], set()
    for ind in alert.get("indicators") or []:
        if isinstance(ind, dict) and ind.get("value") and ind["value"] not in seen:
            seen.add(ind["value"])
            out.append({"type": ind.get("type", "unknown"), "value": ind["value"]})
    for f in ("src_ip", "dst_ip"):
        v = alert.get(f)
        if v and v not in seen:
            seen.add(v)
            out.append({"type": "ip", "value": v})
    return out


def ti_lookup(indicators):
    db = _load_json("threat_intel.json")
    results = []
    for ind in indicators:
        v = ind["value"]
        if _is_internal(v):
            results.append({"indicator": v, "type": "ip", "verdict": "internal",
                            "source": "RFC1918 check", "tags": ["private-address"]})
            continue
        rec = db.get(v)
        if rec and rec.get("simulate") == "timeout":
            results.append({"indicator": v, "type": ind["type"], "verdict": "unavailable",
                            "source": "Synthetic TI feed", "error": "Provider timeout after 10s (simulated)"})
        elif rec:
            results.append({"indicator": v, **{k: rec[k] for k in rec if k != "simulate"}})
        else:
            results.append({"indicator": v, "type": ind["type"], "verdict": "unknown",
                            "source": "No match in feeds", "tags": []})
    return results


def related_alerts(alert):
    host = str(alert.get("host") or "").lower()
    user = str(alert.get("user") or "").lower()
    out = []
    for h in _load_json("alert_history.json"):
        if h["alert_id"] == alert.get("alert_id"):
            continue
        if (host and h.get("host", "").lower() == host) or (user and h.get("user", "").lower() == user):
            out.append(h)
    return out


def execute_action(action, target, case_id, actor):
    """Simulated EDR / firewall / IdP / ticketing action."""
    systems = {"isolate_host": "EDR", "quarantine_file": "EDR", "block_ip": "Firewall",
               "block_domain": "DNS filter", "disable_account": "Identity Provider",
               "reset_password": "Identity Provider", "create_ticket": "ITSM",
               "notify_owner": "E-mail", "monitor": "SIEM watchlist", "close_alert": "SIEM"}
    return {"action_id": "ACT-" + uuid.uuid4().hex[:8].upper(), "action": action, "target": target,
            "system": systems.get(action, "unknown"), "status": "executed (simulated)",
            "case_id": case_id, "actor": actor, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def notify(channel, message):
    return {"channel": channel, "message": message, "status": "sent (simulated)",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

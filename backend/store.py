"""Case store and tamper-evident audit log (SQLite). The audit table is
append-only and hash-chained: each row's hash covers the previous row's hash,
so any edit or deletion is detectable with verify_audit_chain()."""
import hashlib
import json
import sqlite3
import threading
import time

from .config import DB_PATH

_lock = threading.RLock()
_conn = None


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _db():
    global _conn
    if _conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases(
            case_id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT, source TEXT, model TEXT,
            status TEXT, route TEXT, state TEXT, resume_url TEXT);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, case_id TEXT, event TEXT, actor TEXT,
            model TEXT, prompt_version TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
        """)
    return _conn


def _row_to_case(row):
    if not row:
        return None
    d = dict(row)
    d["state"] = json.loads(d["state"])
    return d


def create_case(case_id, source, model, state, status="RUNNING"):
    with _lock:
        if get_case(case_id):
            raise ValueError(f"Case {case_id} already exists")
        t = now()
        _db().execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?)",
                      (case_id, t, t, source, model, status, None, json.dumps(state, default=str), None))
        _db().commit()


def get_case(case_id):
    with _lock:
        return _row_to_case(_db().execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone())


def save_case(case):
    with _lock:
        _db().execute("UPDATE cases SET updated_at=?, status=?, route=?, state=?, resume_url=? WHERE case_id=?",
                      (now(), case["status"], case.get("route"), json.dumps(case["state"], default=str),
                       case.get("resume_url"), case["case_id"]))
        _db().commit()


def list_cases(limit=200):
    with _lock:
        rows = _db().execute("SELECT case_id, created_at, updated_at, source, model, status, route, state "
                             "FROM cases ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [_summarise(r) for r in rows]


def _summarise(r):
    """One dashboard row per case (keeps the UI to a single API call)."""
    st = json.loads(r["state"])
    alert = st.get("alert") if isinstance(st.get("alert"), dict) else {}
    agents = st.get("agents") or {}
    outs = [a.get("output") or {} for a in agents.values()]
    summ = (agents.get("summary") or {}).get("output") or {}
    route = st.get("route") or {}
    val = st.get("validation") or {}
    mitre = sorted({t["id"] for o in outs for t in (o.get("mitre_techniques") or [])
                    if isinstance(t, dict) and t.get("id")})
    return {
        "case_id": r["case_id"], "created_at": r["created_at"], "updated_at": r["updated_at"],
        "source": r["source"], "model": r["model"], "status": r["status"], "route": r["route"],
        "alert_id": alert.get("alert_id"), "rule": alert.get("rule_name"), "host": alert.get("host"),
        "severity": alert.get("severity"), "score": (st.get("score") or {}).get("score"),
        "verdict": summ.get("verdict"), "priority": summ.get("priority"), "confidence": summ.get("confidence"),
        "model_route": route.get("model_route"), "policy_override": bool(route.get("policy_override")),
        "injection": bool(val.get("injection_matches")) or any(o.get("injection_suspected") for o in outs),
        "hallucinations": sum(len(a.get("hallucinations") or []) for a in agents.values()),
        "blocked": sum(len(a.get("blocked") or []) for a in agents.values()),
        "gaps": len(st.get("gaps") or []),
        "agent_failures": sum(1 for a in agents.values() if not a.get("ok")),
        "mitre": mitre,
        "latency_s": round(sum(a.get("latency_s") or 0 for a in agents.values()), 2),
        "pipeline_s": round(sum(s.get("seconds", 0) for s in st.get("steps") or []), 2),
        "decided_by": (st.get("decision") or {}).get("approver"),
    }


def _hash(prev, payload):
    return hashlib.sha256((prev + json.dumps(payload, sort_keys=True, default=str)).encode()).hexdigest()


def audit(case_id, event, actor="system", model=None, prompt_version=None, detail=None):
    with _lock:
        last = _db().execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else "GENESIS"
        ts = now()
        detail_s = json.dumps(detail, default=str) if detail is not None else None
        payload = [ts, case_id, event, actor, model, prompt_version, detail_s]
        _db().execute("INSERT INTO audit(ts, case_id, event, actor, model, prompt_version, detail, prev_hash, hash) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", (*payload, prev, _hash(prev, payload)))
        _db().commit()


def get_audit(case_id=None, limit=1000):
    with _lock:
        if case_id:
            rows = _db().execute("SELECT * FROM audit WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        else:
            rows = _db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def verify_audit_chain():
    with _lock:
        rows = _db().execute("SELECT * FROM audit ORDER BY id").fetchall()
    prev = "GENESIS"
    for r in rows:
        payload = [r["ts"], r["case_id"], r["event"], r["actor"], r["model"], r["prompt_version"], r["detail"]]
        if r["prev_hash"] != prev or r["hash"] != _hash(prev, payload):
            return {"valid": False, "rows_checked": len(rows), "broken_at_id": r["id"]}
        prev = r["hash"]
    return {"valid": True, "rows_checked": len(rows), "broken_at_id": None}

"""SentinelFlow agent & tool services (FastAPI).
n8n orchestrates by calling these endpoints; the Streamlit UI reads cases,
submits HITL decisions and views the audit trail.

Run:  uvicorn backend.main:app --reload --port 8000     (docs at /docs)
"""
import json
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import config, pipeline, store, tools

app = FastAPI(title="SentinelFlow: Governed Agentic SOC services", version="1.0")


class StartReq(BaseModel):
    alert: Any = None
    model: str = config.DEFAULT_MODEL
    case_id: Optional[str] = None
    source: str = "api"
    prompt_version: str = config.PROMPT_VERSION
    backend_url: Optional[str] = None


class StepReq(BaseModel):
    model: Optional[str] = None


class BranchReq(BaseModel):
    resume_url: Optional[str] = None


class DecisionReq(BaseModel):
    decision: str
    approver: str
    role: str
    approved_actions: List[int] = []
    comment: str = ""


class ExecReq(BaseModel):
    via: str = "api"
    decision: Any = None


def _call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except KeyError as e:
        raise HTTPException(404, f"Case not found: {e}")
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/health")
def health():
    return {"status": "ok", "default_model": config.DEFAULT_MODEL, "db": str(config.DB_PATH)}


@app.get("/policy")
def policy():
    return config.POLICY


@app.get("/models")
def models():
    return config.MODELS


@app.get("/test-cases")
def test_cases():
    with open(config.DATA_DIR / "alerts.json", encoding="utf-8") as f:
        return json.load(f)


@app.post("/cases/start")
def start(req: StartReq):
    if req.model not in config.MODELS:
        raise HTTPException(400, f"Unknown model {req.model}")
    return _call(pipeline.start_case, req.alert, req.model, req.case_id, req.source, req.prompt_version, req.backend_url)


@app.post("/cases/{case_id}/steps/{step}")
def step(case_id: str, step: str, req: StepReq = StepReq()):
    return _call(pipeline.run_step, case_id, step, req.model)


@app.post("/cases/{case_id}/branch/{branch}")
def branch(case_id: str, branch: str, req: BranchReq = BranchReq()):
    return _call(pipeline.apply_branch, case_id, branch, req.resume_url)


@app.post("/cases/{case_id}/decision")
def decision(case_id: str, req: DecisionReq):
    return _call(pipeline.record_decision, case_id, req.decision, req.approver, req.role,
                 req.approved_actions, req.comment)


@app.post("/cases/{case_id}/execute")
def execute(case_id: str, req: ExecReq = ExecReq()):
    return _call(pipeline.execute, case_id, req.via)


@app.get("/cases")
def cases(limit: int = 200):
    return store.list_cases(limit)


@app.get("/cases/{case_id}")
def get_case(case_id: str):
    c = store.get_case(case_id)
    if not c:
        raise HTTPException(404, "Case not found")
    return c


@app.post("/triage")
def triage(req: StartReq):
    """In-process engine (fallback when n8n is not running; also used by the benchmark)."""
    if req.model not in config.MODELS:
        raise HTTPException(400, f"Unknown model {req.model}")
    return _call(pipeline.run_pipeline, req.alert, req.model, req.case_id, "python-engine", req.prompt_version)


@app.get("/audit")
def audit(case_id: Optional[str] = None, limit: int = 1000):
    return store.get_audit(case_id, limit)


@app.get("/audit/verify")
def audit_verify():
    return store.verify_audit_chain()


@app.get("/tools/asset/{host}")
def tool_asset(host: str):
    return tools.lookup_asset(host) or {"host": host, "found": False}


@app.post("/tools/ti")
def tool_ti(body: dict):
    return tools.ti_lookup(tools.extract_indicators(body.get("alert") or body))

"""Central configuration and the governance POLICY (single source of truth for
thresholds, allowed actions and roles). Change policy here, not in prompts."""
import json
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env", override=True)

DATA_DIR = ROOT / "data"
DB_PATH = Path(os.getenv("SOC_DB_PATH", str(DATA_DIR / "soc_audit.db")))
N8N_TIMEOUT = 10

PROVIDERS = {
    "groq": {"base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY"},
    "ollama": {"base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"), "key_env": None},
    "mock": {"base_url": None, "key_env": None},
}

with open(ROOT / "config" / "models.json", encoding="utf-8") as f:
    MODELS = json.load(f)

DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "mock")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "90"))
LLM_MIN_INTERVAL = float(os.getenv("LLM_MIN_INTERVAL", "0"))
PROMPT_VERSION = "v3"
STRUCTURED_OUTPUT = os.getenv("STRUCTURED_OUTPUT", "true").lower() == "true"

POLICY = {
    # Deterministic routing thresholds (NIST AI RMF MANAGE: decision thresholds)
    "auto_close_max_score": 30,
    "auto_close_min_confidence": 0.8,
    "escalate_min_score": 70,
    "score_weights": {
        "severity": 8,          # x severity 1-5
        "criticality": 6,       # x asset criticality 1-5 (unknown asset -> 3)
        "ti_malicious": 20,
        "ti_suspicious": 10,
        "per_related_alert": 3,
        "max_related": 5,
    },
    # Action allowlist: models may only recommend these
    "allowed_actions": [
        "close_alert", "create_ticket", "monitor", "notify_owner", "reset_password",
        "disable_account", "isolate_host", "block_ip", "block_domain", "quarantine_file",
    ],
    # Always require a recorded human approval before execution
    "high_impact_actions": [
        "isolate_host", "block_ip", "block_domain", "disable_account", "quarantine_file", "reset_password",
    ],
    # Role-based access control for HITL decisions (higher rank = more authority)
    "roles": {"L1_ANALYST": 1, "L2_ANALYST": 2, "SOC_LEAD": 3},
    "route_required_role": {
        "AUTO_CLOSE": None,
        "ANALYST_REVIEW": "L2_ANALYST",
        "ESCALATE": "SOC_LEAD",
        "EXCEPTION": "L2_ANALYST",
    },
}

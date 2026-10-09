"""Generates n8n/soc_triage_workflow.json (import this file into n8n).
Re-run after editing: python n8n/build_workflow.py"""
import json, uuid
from pathlib import Path

# Every backend response echoes ctx {case_id, model, backend_url}, so each node
# only needs $json (works across n8n versions; no cross-node references).
nodes, conns = [], {}

def nid(): return str(uuid.uuid4())

def add(name, typ, ver, params, pos, **extra):
    nodes.append({"parameters": params, "id": nid(), "name": name, "type": typ,
                  "typeVersion": ver, "position": pos, **extra})

def link(a, b, out=0):
    m = conns.setdefault(a, {"main": []})["main"]
    while len(m) <= out: m.append([])
    m[out].append({"node": b, "type": "main", "index": 0})

def http(name, path, pos, body=None, timeout=180000, ctx="$json.ctx"):
    url = "={{ " + ctx + ".backend_url }}" + path.replace("{CASE}", "/cases/{{ " + ctx + ".case_id }}")
    add(name, "n8n-nodes-base.httpRequest", 4.2, {
        "method": "POST", "url": url,
        "sendBody": True, "specifyBody": "json",
        "jsonBody": body or ("={{ JSON.stringify({ model: " + ctx + ".model }) }}"),
        "options": {"timeout": timeout}}, pos)

CASE = "{CASE}"

add("Security Alert (Webhook)", "n8n-nodes-base.webhook", 2,
    {"httpMethod": "POST", "path": "soc-triage", "responseMode": "onReceived", "options": {}},
    [0, 300], webhookId=nid())

add("SOC Orchestrator", "n8n-nodes-base.code", 2, {"jsCode": """// SOC Orchestrator: entry point of the governed triage workflow.
// Change BACKEND_URL to http://host.docker.internal:8000 if n8n runs in Docker.
const BACKEND_URL = 'http://localhost:8000';
const body = $input.first().json.body || {};
return [{ json: {
  backend_url: BACKEND_URL,
  case_id: body.case_id || ('CASE-N8N-' + Date.now()),
  model: body.model || 'mock',
  alert: body.alert ?? null,
  received_at: new Date().toISOString(),
  plan: ['related_alerts','correlation_agent','ti_lookup','threat_intel_agent','asset_lookup',
         'asset_context_agent','risk_score','risk_agent','summary_agent','route']
}}];"""}, [220, 300])

http("Guardrails: Validate & Sanitise", "/cases/start", [440, 300], ctx="$json",
     body="={{ JSON.stringify({ case_id: $json.case_id, model: $json.model, alert: $json.alert, source: 'n8n', backend_url: $json.backend_url }) }}")

add("Valid Alert?", "n8n-nodes-base.if", 2, {
    "conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose"},
                   "conditions": [{"id": nid(), "leftValue": "={{ $json.valid }}", "rightValue": "",
                                   "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
                   "combinator": "and"}, "options": {}}, [660, 300])

chain = [("Tool: SIEM Related Alerts", "related_alerts"),
         ("Alert Correlation Agent", "correlation_agent"),
         ("Tool: Threat Intel Lookup", "ti_lookup"),
         ("Threat Intelligence Agent", "threat_intel_agent"),
         ("Tool: CMDB Asset Lookup", "asset_lookup"),
         ("Asset Context Agent", "asset_context_agent"),
         ("Risk Scoring Engine (deterministic)", "risk_score"),
         ("Risk / Prioritisation Agent", "risk_agent"),
         ("Incident Summary Agent", "summary_agent"),
         ("Policy Router", "route")]
x = 880
for name, step in chain:
    http(name, CASE + "/steps/" + step, [x, 200]); x += 220

def rule(value, key):
    return {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict"},
                           "conditions": [{"id": nid(), "leftValue": "={{ $json.result.route }}", "rightValue": value,
                                           "operator": {"type": "string", "operation": "equals"}}],
                           "combinator": "and"}, "renameOutput": True, "outputKey": key}

add("Route Switch (A / H / E)", "n8n-nodes-base.switch", 3.2, {
    "rules": {"values": [rule("AUTO_CLOSE", "A: Auto-close"), rule("ANALYST_REVIEW", "H: Analyst review"),
                         rule("ESCALATE", "E: Escalate"), rule("EXCEPTION", "E: Exception")]},
    "options": {}}, [x, 200])
sx = x + 260
http("A: Auto-close & Log", CASE + "/branch/auto_close", [sx, 0], body="={{ JSON.stringify({}) }}")
http("E: Notify IR Lead (Escalation)", CASE + "/branch/escalate", [sx, 420], body="={{ JSON.stringify({}) }}")
http("E: Exception Queue", CASE + "/branch/exception", [sx, 640], body="={{ JSON.stringify({}) }}")
http("H: Register Pending Approval", CASE + "/branch/await_approval", [sx + 260, 220],
     body="={{ JSON.stringify({ resume_url: $execution.resumeUrl }) }}")
add("H: Wait for Human Decision", "n8n-nodes-base.wait", 1.1,
    {"resume": "webhook", "httpMethod": "POST", "options": {}}, [sx + 520, 220], webhookId=nid())
http("Execute Approved Response", CASE + "/execute", [sx + 780, 220], ctx="$json.body.ctx",
     body="={{ JSON.stringify({ via: 'n8n', decision: $json.body.decision }) }}")

add("Note: A/H/E legend", "n8n-nodes-base.stickyNote", 1, {"content":
    "## Governed SOC triage\n**A** = Autonomous (agents, tools, auto-close of low-risk FPs)\n"
    "**H** = Human-in-the-loop (Wait node: analyst approves/rejects in the UI)\n"
    "**E** = Escalation (IR lead paged; exception queue for incomplete context)\n\n"
    "Routing thresholds live in backend policy code, not in prompts.", "height": 220, "width": 420}, [0, -40])
add("Note: Agents", "n8n-nodes-base.stickyNote", 1, {"content":
    "### A: Autonomous agent chain\nEach agent = STOIC prompt + open-weight model + schema validation + grounding checks.\n"
    "Tools = SIEM, Threat Intel, CMDB (synthetic).", "height": 160, "width": 520}, [880, 20])
add("Note: HITL", "n8n-nodes-base.stickyNote", 1, {"content":
    "### H: No containment without a recorded human approval\nBackend blocks /execute unless an approved decision exists (RBAC: L2 for review, SOC Lead for escalations).",
    "height": 160, "width": 560}, [sx + 260, 380])

link("Security Alert (Webhook)", "SOC Orchestrator")
link("SOC Orchestrator", "Guardrails: Validate & Sanitise")
link("Guardrails: Validate & Sanitise", "Valid Alert?")
link("Valid Alert?", chain[0][0], 0)
link("Valid Alert?", "E: Exception Queue", 1)
for (a, _), (b, _) in zip(chain, chain[1:]):
    link(a, b)
link(chain[-1][0], "Route Switch (A / H / E)")
link("Route Switch (A / H / E)", "A: Auto-close & Log", 0)
link("Route Switch (A / H / E)", "H: Register Pending Approval", 1)
link("Route Switch (A / H / E)", "E: Notify IR Lead (Escalation)", 2)
link("Route Switch (A / H / E)", "E: Exception Queue", 3)
link("E: Notify IR Lead (Escalation)", "H: Register Pending Approval")
link("H: Register Pending Approval", "H: Wait for Human Decision")
link("H: Wait for Human Decision", "Execute Approved Response")

wf = {"name": "SentinelFlow: Governed SOC Alert Triage", "nodes": nodes, "connections": conns,
      "active": False, "settings": {"executionOrder": "v1"}, "pinData": {}, "tags": []}
out = Path(__file__).with_name("soc_triage_workflow.json")
out.write_text(json.dumps(wf, indent=2))
print(f"wrote {out} with {len(nodes)} nodes")

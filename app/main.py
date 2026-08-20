import re
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ---- Assigned scope ----
TENANT = "tenant-lsv576g"
EMAIL_DOMAIN = "notify-4axg80p.example"

ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}

# ---- Structural HTML safety patterns (not a phrase/keyword blocklist —
# these match actual dangerous HTML constructs, not natural-language content) ----
SCRIPT_RE = re.compile(r"<\s*script\b", re.IGNORECASE)
IFRAME_RE = re.compile(r"<\s*iframe\b", re.IGNORECASE)
EVENT_HANDLER_RE = re.compile(r"\bon[a-zA-Z]+\s*=", re.IGNORECASE)
JS_URL_RE = re.compile(r"javascript\s*:", re.IGNORECASE)


def is_unsafe_html(html: str) -> bool:
    return bool(
        SCRIPT_RE.search(html)
        or IFRAME_RE.search(html)
        or EVENT_HANDLER_RE.search(html)
        or JS_URL_RE.search(html)
    )


def result(decision: str, reason: str) -> JSONResponse:
    return JSONResponse({"decision": decision, "reason": reason})


@app.post("/action-firewall")
async def action_firewall(request: Request):
    # ---- Parse body ----
    try:
        body = await request.json()
    except Exception:
        return result("block", "INVALID_SCHEMA")

    if not isinstance(body, dict):
        return result("block", "INVALID_SCHEMA")
    
    if set(body.keys()) - {"provenance", "humanApproved", "untrustedContent", "action"}:
    return result("block", "INVALID_SCHEMA")

    provenance = body.get("provenance")
    human_approved = body.get("humanApproved")
    untrusted_content = body.get("untrustedContent", None)
    action = body.get("action")

    # ---- 1. Top-level schema ----
    if provenance not in ("trusted", "untrusted"):
        return result("block", "INVALID_SCHEMA")
    if not isinstance(human_approved, bool):
        return result("block", "INVALID_SCHEMA")
    if untrusted_content is not None and not isinstance(untrusted_content, str):
        return result("block", "INVALID_SCHEMA")
    if not isinstance(action, dict):
        return result("block", "INVALID_SCHEMA")
    if set(action.keys()) - {"tool", "args"}:
        return result("block", "INVALID_SCHEMA")

    tool = action.get("tool")
    args = action.get("args")

    if not isinstance(tool, str):
        return result("block", "INVALID_SCHEMA")
    if not isinstance(args, dict):
        return result("block", "INVALID_SCHEMA")

    # ---- 2. Tool allowlist ----
    if tool not in ALLOWED_TOOLS:
        return result("block", "TOOL_NOT_ALLOWED")

    # ---- 3. Selected tool's argument schema (+ later stage checks) ----
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return result("block", "INVALID_SCHEMA")
        query = args.get("query")
        if not isinstance(query, str) or not (1 <= len(query) <= 200):
            return result("block", "INVALID_SCHEMA")

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return result("block", "INVALID_SCHEMA")
        tenant_id = args.get("tenantId")
        record_id = args.get("recordId")
        if not isinstance(tenant_id, str) or not isinstance(record_id, str):
            return result("block", "INVALID_SCHEMA")
        if len(tenant_id) == 0 or len(record_id) == 0:
            return result("block", "INVALID_SCHEMA")

        # ---- 4. Tenant scope ----
        if tenant_id != TENANT:
            return result("block", "TENANT_SCOPE")

    elif tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return result("block", "INVALID_SCHEMA")
        to = args.get("to")
        subject = args.get("subject")
        body_ = args.get("body")
        if not isinstance(to, str) or not isinstance(subject, str) or not isinstance(body_, str):
            return result("block", "INVALID_SCHEMA")
        if len(to) == 0 or len(subject) == 0 or len(body_) == 0:
            return result("block", "INVALID_SCHEMA")

        # ---- 5. Exact email domain (egress) ----
        if "@" not in to or to.count("@") != 1:
            return result("block", "EGRESS_DENIED")
        local, domain = to.split("@", 1)
        if not local or domain != EMAIL_DOMAIN:
            return result("block", "EGRESS_DENIED")

        # ---- 6. Human approval ----
        if human_approved is not True:
            return result("block", "APPROVAL_REQUIRED")

    elif tool == "render_html":
        if set(args.keys()) != {"html"}:
            return result("block", "INVALID_SCHEMA")
        html = args.get("html")
        if not isinstance(html, str):
            return result("block", "INVALID_SCHEMA")

        # ---- 7. HTML safety ----
        if is_unsafe_html(html):
            return result("block", "UNSAFE_OUTPUT")

    return result("allow", "ALLOW")


@app.get("/")
async def root():
    return {"status": "ok", "service": "llm-action-firewall"}

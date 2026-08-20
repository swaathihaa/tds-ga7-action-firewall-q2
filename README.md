# LLM Action Firewall

Deterministic FastAPI firewall for validating model-generated tool actions before execution.

## Endpoint

POST `/action-firewall`

The firewall validates schemas, tool allowlists, tenant scope, email egress, human approval, and HTML safety without using an LLM or phrase-based guardrails.

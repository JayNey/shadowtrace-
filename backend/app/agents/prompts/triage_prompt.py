"""TriageAgent LLM prompt templates (ISSUE-032).

Provides the system prompt with entity type definitions and two few-shot
examples, plus a helper to build the full message list for an LLM call.

The ``TriageLLMResponse`` wrapper model bridges the prompt's three-key output
(``event_type``, ``entities``, ``decision_summary``) and the ``EntitySet`` model so
that LLM responses validate correctly — fixing the prompt/response_model
mismatch noted in the PR review.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.llm.base import LLMMessage
from app.models.entities import EntitySet
from app.models.enums import EventType

_MAX_TRIAGE_SUMMARY_CHARS = 512


class TriageLLMResponse(BaseModel):
    """Wrapper that matches the three top-level keys the prompt asks for.

    The prompt's few-shot examples produce ``event_type``, ``entities``, and
    ``decision_summary`` at the top level.  Passing ``EntitySet`` directly as the
    ``response_model`` would reject ``event_type`` and ``decision_summary`` as
    forbidden extra fields.  This wrapper accepts all three; the agent then
    extracts ``.entities`` for downstream use.
    """

    model_config = ConfigDict(extra="forbid")

    event_type: EventType
    entities: EntitySet = Field(default_factory=EntitySet)
    decision_summary: str = Field(default="", max_length=_MAX_TRIAGE_SUMMARY_CHARS)
    # Deprecated ISSUE-131: legacy key retained for parse compatibility only.
    reasoning: str = Field(default="", deprecated=True)

    @field_validator("decision_summary")
    @classmethod
    def _bound_summary(cls, value: str) -> str:
        return value[:_MAX_TRIAGE_SUMMARY_CHARS]

    @field_validator("reasoning")
    @classmethod
    def _reject_legacy_reasoning(cls, value: str) -> str:
        return ""


ENTITY_TYPE_DEFINITIONS = """
Entity types to extract (only these six categories):
- account: A user or service account name (e.g. "zhangsan", "svc-backup", "admin@corp.local").
- host: A machine hostname (e.g. "PC-FIN-023", "web-server-01").
- ip: An IPv4 address with scope hint ("external" or "internal").
- domain: A fully-qualified domain name (e.g. "unknown-upload-example.com").
- process: A process binary name with optional command line
  (e.g. "powershell.exe", "7z.exe a -p archive.7z").
- file: A file name with extension (e.g. "finance_report.zip", "data.csv").
"""

FEW_SHOT_EXAMPLE_1 = """
Alert: "Account zhangsan on host PC-FIN-023 executed powershell.exe which compressed \
finance_report.zip via 7z.exe and uploaded to 203.0.113.88 \
(unknown-upload-example.com). Source IP 45.153.12.88 triggered geographic anomaly."

Expected output:
{
  "event_type": "data_exfiltration",
  "entities": {
    "accounts": [
      {"entity_type": "account", "username": "zhangsan",
       "entity_id": "acct-zhangsan"}
    ],
    "hosts": [
      {"entity_type": "host", "hostname": "PC-FIN-023",
       "entity_id": "host-pcfin023"}
    ],
    "ips": [
      {"entity_type": "ip", "address": "203.0.113.88",
       "scope": "external", "entity_id": "ip-20300113088"},
      {"entity_type": "ip", "address": "45.153.12.88",
       "scope": "external", "entity_id": "ip-4515301288"}
    ],
    "domains": [
      {"entity_type": "domain", "fqdn": "unknown-upload-example.com",
       "entity_id": "dom-unknownupload"}
    ],
    "processes": [
      {"entity_type": "process", "name": "powershell.exe",
       "entity_id": "proc-powershell"},
      {"entity_type": "process", "name": "7z.exe",
       "entity_id": "proc-7z"}
    ],
    "files": [
      {"entity_type": "file", "name": "finance_report.zip",
       "entity_id": "file-financereport"}
    ]
  },
  "decision_summary": "Insider data exfiltration pattern: account compressed \
sensitive file and uploaded to external IP and domain."
}
"""  # noqa: E501

FEW_SHOT_EXAMPLE_2 = """
Alert: "User svc-backup failed to login 1 time from 10.50.1.10 \
to host PC-OPS-JUMP-01."

Expected output:
{
  "event_type": "account_anomaly",
  "entities": {
    "accounts": [
      {"entity_type": "account", "username": "svc-backup",
       "entity_id": "acct-svcbackup"}
    ],
    "hosts": [
      {"entity_type": "host", "hostname": "PC-OPS-JUMP-01",
       "entity_id": "host-pcopsjump01"}
    ],
    "ips": [
      {"entity_type": "ip", "address": "10.50.1.10",
       "scope": "internal", "entity_id": "ip-10500110"}
    ],
    "domains": [],
    "processes": [],
    "files": []
  },
  "decision_summary": "Single failed login from internal IP; likely not a threat."
}
"""  # noqa: E501

TRIAGE_SYSTEM_PROMPT: str = (
    f"You are a security triage specialist. Your job is to parse a security alert "
    f"and extract structured entities and event type information.\n\n"
    f"{ENTITY_TYPE_DEFINITIONS}"
    f"""
Event types (choose exactly one):
- data_exfiltration: Unauthorized data transfer to external destination.
- insider_threat: Internal user performing suspicious actions.
- malicious_process: Malicious or suspicious process execution.
- suspicious_domain: Communication with suspicious or known-bad domains.
- lateral_movement: Internal host-to-host movement patterns.
- host_compromise: Evidence of host-level compromise.
- account_anomaly: Unusual account behavior (login anomalies, privilege changes).
- other: None of the above clearly applies.

Few-shot examples:
{FEW_SHOT_EXAMPLE_1}

{FEW_SHOT_EXAMPLE_2}

Always output valid JSON with these top-level keys: event_type, entities, decision_summary.
Entities must follow the exact field schema shown in the examples.
decision_summary must be a bounded structured summary (max 512 chars) — never chain-of-thought.
If no entities of a category are found, return an empty list for that category."""
)


def build_triage_messages(alert_text: str) -> list[LLMMessage]:
    """Return ``[system, user]`` messages for the LLM entity-extraction call.

    Args:
        alert_text: The raw alert text / summary to parse.  Must be a non-empty
            string.  Callers are responsible for truncating excessively long
            inputs before calling this function.

    Returns:
        A two-element message list ready for ``BaseLLMClient.chat``.

    Raises:
        ValueError: If *alert_text* is None or an empty string.
    """
    if not alert_text or not isinstance(alert_text, str):
        raise ValueError(
            f"alert_text must be a non-empty string, got {type(alert_text).__name__!r}"
        )
    return [
        LLMMessage(role="system", content=TRIAGE_SYSTEM_PROMPT),
        LLMMessage(role="user", content=f"Alert: {alert_text}"),
    ]


__all__ = [
    "TriageLLMResponse",
    "TRIAGE_SYSTEM_PROMPT",
    "build_triage_messages",
]

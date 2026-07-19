import json
from typing import Any


class InvestigationPromptBuilder:

    @staticmethod
    def _json_dump(
        value: Any,
    ) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            default=str,
        )

    @staticmethod
    def build(
        incident: dict[str, Any],
        evidence: dict[str, Any],
        blockchain_verification: dict[str, Any],
        alert: dict[str, Any] | None = None,
        timeline: list[dict[str, Any]] | None = None,
        indicators: list[dict[str, Any]] | None = None,
        mitre_techniques: list[
            dict[str, Any]
        ] | None = None,
    ) -> str:
        alert = alert or {}
        timeline = timeline or []
        indicators = indicators or []
        mitre_techniques = (
            mitre_techniques or []
        )

        risk_score = alert.get(
            "risk_score"
        )

        risk_level = (
            alert.get("severity")
            or incident.get("severity")
            or "UNKNOWN"
        )

        alert_reason = (
            alert.get("reason")
            or incident.get("description")
            or "No detection reason provided."
        )

        evidence_integrity = bool(
            blockchain_verification.get(
                "is_valid",
                blockchain_verification.get(
                    "verified",
                    False,
                ),
            )
        )

        context = {
            "incident": incident,
            "alert": alert,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "alert_reason": alert_reason,
            "evidence": evidence,
            "timeline": timeline,
            "indicators": indicators,
            "mitre_techniques": (
                mitre_techniques
            ),
            "blockchain_verification": (
                blockchain_verification
            ),
            "evidence_integrity_verified": (
                evidence_integrity
            ),
        }

        return f"""
You are a senior SOC analyst and digital forensics investigator.

Analyze the following insider-threat incident and produce a professional security investigation report.

The report must be based only on the supplied investigation context. Do not invent usernames, risk scores, source IPs, processes, MITRE techniques, timestamps, or indicators.

INVESTIGATION CONTEXT

{InvestigationPromptBuilder._json_dump(context)}

REPORT REQUIREMENTS

Return a structured investigation report with the following sections:

1. Executive Summary

Summarize:
- the affected user
- incident severity
- risk score
- primary suspicious behavior
- whether immediate action is required

Do not write "unknown" when the risk score is available in the alert data.

2. Technical Analysis

Include:
- incident ID
- alert type
- affected username
- actor username, when available
- target username or member username, when available
- risk score
- severity
- source IP
- computer or host
- process name
- command line
- parent process
- privileges
- privileged group name
- event IDs
- timeline events
- alert reason
- evidence integrity result
- blockchain verification result

Use only fields present in the investigation context.

If indicators exist, list the most important indicators clearly.

3. MITRE ATT&CK Mapping

For every supplied MITRE technique, include:
- technique ID
- technique name
- tactic

Do not state that no MITRE techniques were identified when the mitre_techniques list is not empty.

4. Findings

Explain:
- why the activity is suspicious
- whether it may indicate brute force, persistence, privilege escalation, credential access, execution, lateral movement, or defense evasion
- the likely security impact

5. Recommendations

Provide prioritized containment and investigation actions, such as:
- disable or restrict the affected account
- review privileged group membership
- isolate the host
- investigate source IP
- collect process and command-line artifacts
- reset credentials
- review related Windows events
- preserve evidence
- validate the blockchain audit chain

6. Confidence

Provide a confidence score between 0.0 and 1.0 based on the quality and completeness of the supplied evidence.

OUTPUT FORMAT

Return valid JSON with exactly these fields:

{{
  "summary": "string",
  "analysis": "string",
  "recommendations": [
    "string"
  ],
  "mitre_techniques": [
    {{
      "technique_id": "string",
      "technique_name": "string",
      "tactic": "string"
    }}
  ],
  "confidence": 0.0
}}
""".strip()
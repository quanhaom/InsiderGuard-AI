import json
from typing import Any


class InvestigationPromptBuilder:

    SYSTEM_INSTRUCTION = """
You are a senior SOC analyst and digital forensics investigator.

Your task is to explain a security incident using only the supplied
evidence. Do not invent facts, users, files, devices, events, or
MITRE ATT&CK techniques.

The risk score and blockchain verification result are authoritative.
You must not modify them.

Produce:
1. Executive summary
2. Behavioral analysis
3. Triggered indicators
4. Investigation recommendations
5. Relevant MITRE ATT&CK techniques only when supported
6. Confidence score from 0 to 100
""".strip()

    @classmethod
    def build(
        cls,
        *,
        incident: dict[str, Any],
        evidence: dict[str, Any],
        blockchain_verification: dict[str, Any]
    ) -> str:
        context = {
            "incident": incident,
            "evidence": evidence,
            "blockchain_verification": blockchain_verification
        }

        normalized_context = json.dumps(
            context,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            default=str
        )

        return (
            f"{cls.SYSTEM_INSTRUCTION}\n\n"
            "SECURITY CONTEXT:\n"
            f"{normalized_context}"
        )
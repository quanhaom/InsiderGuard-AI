from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):

    @property
    @abstractmethod
    def model_name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def generate_report(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        raise NotImplementedError


class MockInvestigationLLM(LLMProvider):

    @property
    def model_name(self) -> str:
        return "mock-investigator-v1"

    def generate_report(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        incident = context["incident"]
        evidence = context["evidence"]
        blockchain = context["blockchain_verification"]

        snapshot = evidence.get("snapshot", {})
        risk = snapshot.get("risk_assessment") or {}
        behavior = snapshot.get("behavior_profile") or {}
        indicators = snapshot.get("indicators") or []

        username = incident.get("username", "unknown user")
        risk_score = risk.get("risk_score", "unknown")
        risk_level = risk.get(
            "risk_level",
            incident.get("severity", "UNKNOWN")
        )

        indicator_text = (
            ", ".join(indicators)
            if indicators
            else "No indicators were recorded"
        )

        average_hour = behavior.get("avg_login_hour")
        common_ip = behavior.get("common_source_ip")

        analysis_parts = [
            (
                f"The incident involves user {username} and has "
                f"a deterministic risk score of {risk_score} "
                f"with level {risk_level}."
            ),
            f"Triggered indicators: {indicator_text}."
        ]

        if average_hour is not None:
            analysis_parts.append(
                f"The historical average login hour is {average_hour}."
            )

        if common_ip:
            analysis_parts.append(
                f"The historical common source IP is {common_ip}."
            )

        evidence_valid = blockchain.get("is_valid", False)

        if evidence_valid:
            integrity_statement = (
                "The evidence and audit chain passed integrity "
                "verification."
            )
        else:
            integrity_statement = (
                "The evidence or audit chain did not pass integrity "
                "verification. Manual validation is required."
            )

        analysis_parts.append(integrity_statement)

        recommendations = [
            "Review the complete authentication timeline.",
            "Validate the source IP and originating device.",
            "Review file, USB, email, process, and network activity.",
            "Confirm whether the activity was authorized by the user."
        ]

        if risk_level in {"HIGH", "CRITICAL"}:
            recommendations.insert(
                0,
                "Place the account under enhanced monitoring."
            )

        confidence = 85.0 if evidence_valid else 55.0

        return {
            "summary": (
                f"A {risk_level} insider-risk incident was detected "
                f"for user {username}."
            ),
            "analysis": " ".join(analysis_parts),
            "recommendations": recommendations,
            "mitre_techniques": [],
            "confidence": confidence
        }
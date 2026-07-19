
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
        context: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError


class MockInvestigationLLM(LLMProvider):

    @property
    def model_name(self) -> str:
        return "mock-investigator-v2"

    @staticmethod
    def _format_indicator(
        indicator: Any,
    ) -> str:
        if isinstance(indicator, dict):
            indicator_type = (
                indicator.get("type")
                or "indicator"
            )

            value = indicator.get(
                "value"
            )

            source = indicator.get(
                "source"
            )

            text = (
                f"{indicator_type}: {value}"
            )

            if source:
                text += f" ({source})"

            return text

        return str(indicator)

    @staticmethod
    def _format_mitre(
        technique: Any,
    ) -> str:
        if not isinstance(
            technique,
            dict,
        ):
            return str(technique)

        technique_id = (
            technique.get(
                "technique_id"
            )
            or technique.get("id")
            or "UNKNOWN"
        )

        technique_name = (
            technique.get(
                "technique_name"
            )
            or technique.get("name")
            or "Unknown"
        )

        tactic = (
            technique.get("tactic")
            or "Unknown"
        )

        return (
            f"{technique_id} - "
            f"{technique_name} "
            f"({tactic})"
        )

    @staticmethod
    def _get_first_indicator_value(
        indicators: list[Any],
        indicator_type: str,
    ) -> Any:
        for indicator in indicators:
            if not isinstance(
                indicator,
                dict,
            ):
                continue

            if (
                indicator.get("type")
                == indicator_type
            ):
                return indicator.get(
                    "value"
                )

        return None

    def generate_report(
        self,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        incident = (
            context.get("incident")
            or {}
        )

        alert = (
            context.get("alert")
            or {}
        )

        evidence = (
            context.get("evidence")
            or {}
        )

        timeline = (
            context.get("timeline")
            or []
        )

        normalized_events = (
            context.get(
                "normalized_events"
            )
            or []
        )

        indicators = (
            context.get("indicators")
            or []
        )

        mitre_techniques = (
            context.get(
                "mitre_techniques"
            )
            or []
        )

        blockchain = (
            context.get(
                "blockchain_verification"
            )
            or {}
        )

        username = (
            incident.get("username")
            or alert.get("username")
            or "unknown user"
        )

        risk_score = (
            context.get("risk_score")
        )

        if risk_score is None:
            risk_score = alert.get(
                "risk_score"
            )

        if risk_score is None:
            snapshot = (
                evidence.get("snapshot")
                or {}
            )

            risk_assessment = (
                snapshot.get(
                    "risk_assessment"
                )
                or {}
            )

            risk_score = (
                risk_assessment.get(
                    "risk_score"
                )
            )

        risk_level = (
            context.get("risk_level")
            or alert.get("severity")
            or incident.get("severity")
            or "UNKNOWN"
        )

        alert_type = (
            alert.get("alert_type")
            or "UNKNOWN"
        )

        alert_reason = (
            alert.get("reason")
            or incident.get(
                "description"
            )
            or (
                "No detection reason "
                "was provided."
            )
        )

        if risk_score is None:
            risk_score_text = (
                "not available"
            )
        else:
            risk_score_text = str(
                risk_score
            )

        indicator_lines = [
            self._format_indicator(
                indicator
            )
            for indicator
            in indicators
        ]

        if indicator_lines:
            indicator_text = "; ".join(
                indicator_lines
            )
        else:
            indicator_text = (
                "No additional indicators "
                "were extracted."
            )

        source_ip = (
            self._get_first_indicator_value(
                indicators,
                "source_ip",
            )
        )

        computer = (
            self._get_first_indicator_value(
                indicators,
                "computer",
            )
        )

        process_name = (
            self._get_first_indicator_value(
                indicators,
                "process_name",
            )
        )

        command_line = (
            self._get_first_indicator_value(
                indicators,
                "command_line",
            )
        )

        actor_username = (
            self._get_first_indicator_value(
                indicators,
                "actor_username",
            )
        )

        target_username = (
            self._get_first_indicator_value(
                indicators,
                "target_username",
            )
            or self
            ._get_first_indicator_value(
                indicators,
                "member_username",
            )
        )

        group_name = (
            self._get_first_indicator_value(
                indicators,
                "group_name",
            )
        )

        dangerous_privileges = (
            self._get_first_indicator_value(
                indicators,
                "dangerous_privileges",
            )
            or self
            ._get_first_indicator_value(
                indicators,
                "privileges",
            )
        )

        analysis_parts = [
            (
                f"The incident involves user "
                f"{username}."
            ),
            (
                f"The associated alert type is "
                f"{alert_type}."
            ),
            (
                f"The deterministic risk score "
                f"is {risk_score_text} with "
                f"severity level {risk_level}."
            ),
            (
                f"Detection reason: "
                f"{alert_reason}"
            ),
            (
                f"Triggered indicators: "
                f"{indicator_text}"
            ),
        ]

        if actor_username:
            analysis_parts.append(
                f"Actor account: "
                f"{actor_username}."
            )

        if target_username:
            analysis_parts.append(
                f"Target account: "
                f"{target_username}."
            )

        if group_name:
            analysis_parts.append(
                f"Privileged group: "
                f"{group_name}."
            )

        if source_ip:
            analysis_parts.append(
                f"Source IP: "
                f"{source_ip}."
            )

        if computer:
            analysis_parts.append(
                f"Source host: "
                f"{computer}."
            )

        if process_name:
            analysis_parts.append(
                f"Observed process: "
                f"{process_name}."
            )

        if command_line:
            analysis_parts.append(
                f"Command line: "
                f"{command_line}."
            )

        if dangerous_privileges:
            analysis_parts.append(
                f"Assigned privileges: "
                f"{dangerous_privileges}."
            )

        if timeline:
            timeline_types = [
                str(
                    item.get(
                        "event_type",
                        "UNKNOWN",
                    )
                )
                for item in timeline
                if isinstance(
                    item,
                    dict,
                )
            ]

            if timeline_types:
                analysis_parts.append(
                    "Incident timeline events: "
                    + ", ".join(
                        timeline_types
                    )
                    + "."
                )

        if normalized_events:
            event_ids = []

            for event in (
                normalized_events
            ):
                if not isinstance(
                    event,
                    dict,
                ):
                    continue

                event_id = event.get(
                    "event_id"
                )

                if (
                    event_id is not None
                    and event_id
                    not in event_ids
                ):
                    event_ids.append(
                        event_id
                    )

            if event_ids:
                analysis_parts.append(
                    "Related Windows Event IDs: "
                    + ", ".join(
                        str(event_id)
                        for event_id
                        in event_ids
                    )
                    + "."
                )

        evidence_valid = bool(
            blockchain.get(
                "is_valid",
                blockchain.get(
                    "verified",
                    False,
                ),
            )
        )

        if evidence_valid:
            integrity_statement = (
                "The evidence hash and "
                "blockchain audit chain "
                "passed integrity verification."
            )
        else:
            integrity_statement = (
                "The evidence or blockchain "
                "audit chain did not pass "
                "integrity verification. "
                "Manual validation is required."
            )

        analysis_parts.append(
            integrity_statement
        )

        mitre_lines = [
            self._format_mitre(
                technique
            )
            for technique
            in mitre_techniques
        ]

        if mitre_lines:
            mitre_summary = (
                "MITRE ATT&CK techniques: "
                + "; ".join(
                    mitre_lines
                )
                + "."
            )

            analysis_parts.append(
                mitre_summary
            )

        recommendations = [
            (
                "Review the complete incident "
                "timeline and related Windows "
                "security events."
            ),
            (
                "Validate the source IP, "
                "originating device, and actor "
                "account."
            ),
            (
                "Review authentication, process, "
                "file, USB, email, and network "
                "activity associated with the "
                "affected user."
            ),
            (
                "Preserve all relevant evidence "
                "and revalidate the blockchain "
                "audit chain."
            ),
            (
                "Confirm whether the detected "
                "activity was authorized."
            ),
        ]

        if risk_level in {
            "HIGH",
            "CRITICAL",
        }:
            recommendations.insert(
                0,
                (
                    "Place the affected account "
                    "under enhanced monitoring "
                    "and consider temporary "
                    "access restriction."
                ),
            )

        if group_name:
            recommendations.insert(
                1,
                (
                    "Review and, if unauthorized, "
                    f"remove membership from "
                    f"{group_name}."
                ),
            )

        if process_name:
            recommendations.insert(
                1,
                (
                    "Collect the process image, "
                    "command line, parent process, "
                    "hashes, and associated "
                    "network activity."
                ),
            )

        if source_ip:
            recommendations.append(
                (
                    f"Investigate source IP "
                    f"{source_ip} for related "
                    "activity."
                )
            )

        if evidence_valid:
            confidence = 0.92
        else:
            confidence = 0.65

        if not indicators:
            confidence -= 0.10

        if risk_score is None:
            confidence -= 0.10

        confidence = max(
            0.0,
            min(
                confidence,
                1.0,
            ),
        )

        summary_parts = [
            (
                f"A {risk_level} insider-risk "
                f"incident was detected for "
                f"user {username}."
            )
        ]

        if alert_type != "UNKNOWN":
            summary_parts.append(
                (
                    f"The primary detection was "
                    f"{alert_type}."
                )
            )

        if risk_score is not None:
            summary_parts.append(
                (
                    f"The calculated risk score "
                    f"was {risk_score}."
                )
            )

        if group_name:
            summary_parts.append(
                (
                    f"The activity involved the "
                    f"privileged group "
                    f"{group_name}."
                )
            )

        if process_name:
            summary_parts.append(
                (
                    f"The process "
                    f"{process_name} was observed."
                )
            )

        return {
            "summary": " ".join(
                summary_parts
            ),
            "analysis": " ".join(
                analysis_parts
            ),
            "recommendations": (
                recommendations
            ),
            "mitre_techniques": (
                mitre_techniques
            ),
            "confidence": confidence,
        }

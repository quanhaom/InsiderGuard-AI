import json
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident_event import IncidentEvent
from app.models.investigation_report import (
    InvestigationReport,
)
from app.models.normalized_windows_event import (
    NormalizedWindowsEvent,
)

from app.modules.blockchain.service import (
    BlockchainService,
)
from app.modules.investigator.llm import (
    LLMProvider,
    MockInvestigationLLM,
)
from app.modules.investigator.prompt_builder import (
    InvestigationPromptBuilder,
)

from app.repositories.evidence_repository import (
    EvidenceRepository,
)
from app.repositories.incident_repository import (
    IncidentRepository,
)
from app.repositories.investigation_repository import (
    InvestigationRepository,
)


class InvestigatorService:

    EVENT_MITRE_MAP: dict[str, list[dict[str, Any]]] = {
        "FAILED_LOGIN_BURST": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
            }
        ],
        "PRIVILEGE_ESCALATION": [
            {
                "technique_id": "T1068",
                "technique_name": (
                    "Exploitation for Privilege Escalation"
                ),
                "tactic": "Privilege Escalation",
            }
        ],
        "PRIVILEGE_ESCALATION_DETECTED": [
            {
                "technique_id": "T1068",
                "technique_name": (
                    "Exploitation for Privilege Escalation"
                ),
                "tactic": "Privilege Escalation",
            }
        ],
        "SUSPICIOUS_PROCESS": [
            {
                "technique_id": "T1059",
                "technique_name": (
                    "Command and Scripting Interpreter"
                ),
                "tactic": "Execution",
            }
        ],
        "SUSPICIOUS_PROCESS_DETECTED": [
            {
                "technique_id": "T1059",
                "technique_name": (
                    "Command and Scripting Interpreter"
                ),
                "tactic": "Execution",
            }
        ],
        "USER_ACCOUNT_CREATED": [
            {
                "technique_id": "T1136",
                "technique_name": "Create Account",
                "tactic": "Persistence",
            }
        ],
        "PRIVILEGED_GROUP_MEMBERSHIP": [
            {
                "technique_id": "T1098",
                "technique_name": "Account Manipulation",
                "tactic": (
                    "Persistence / Privilege Escalation"
                ),
            }
        ],
        "GROUP_MEMBERSHIP_CHANGED": [
            {
                "technique_id": "T1098",
                "technique_name": "Account Manipulation",
                "tactic": (
                    "Persistence / Privilege Escalation"
                ),
            }
        ],
    }

    @staticmethod
    def _make_json_serializable(
        value: Any,
    ) -> Any:
        if isinstance(
            value,
            (datetime, date),
        ):
            return value.isoformat()

        if isinstance(
            value,
            Enum,
        ):
            return value.value

        if isinstance(
            value,
            UUID,
        ):
            return str(value)

        if isinstance(
            value,
            dict,
        ):
            return {
                str(key): (
                    InvestigatorService
                    ._make_json_serializable(
                        item
                    )
                )
                for key, item
                in value.items()
            }

        if isinstance(
            value,
            (list, tuple, set),
        ):
            return [
                InvestigatorService
                ._make_json_serializable(
                    item
                )
                for item in value
            ]

        return value

    @staticmethod
    def _parse_json_value(
        value: Any,
        fallback_key: str = "raw_value",
    ) -> Any:
        if value is None:
            return None

        if isinstance(
            value,
            (dict, list),
        ):
            return value

        if isinstance(
            value,
            str,
        ):
            try:
                return json.loads(
                    value
                )
            except json.JSONDecodeError:
                return {
                    fallback_key: value
                }

        return (
            InvestigatorService
            ._make_json_serializable(
                value
            )
        )

    @staticmethod
    def _serialize_incident(
        incident,
    ) -> dict[str, Any]:
        return {
            "id": incident.id,
            "alert_id": incident.alert_id,
            "username": incident.username,
            "title": incident.title,
            "severity": incident.severity,
            "description": (
                incident.description
            ),
            "status": incident.status,
            "detected_at": (
                incident.created_at
            ),
            "resolved_at": (
                incident.closed_at
            ),
        }

    @staticmethod
    def _serialize_alert(
        alert: Alert | None,
    ) -> dict[str, Any] | None:
        if alert is None:
            return None

        return {
            "id": alert.id,
            "username": alert.username,
            "alert_type": (
                alert.alert_type
            ),
            "severity": alert.severity,
            "risk_score": (
                alert.risk_score
            ),
            "reason": alert.reason,
            "created_at": (
                getattr(
                    alert,
                    "created_at",
                    None,
                )
            ),
        }

    @staticmethod
    def _serialize_evidence(
        evidence,
    ) -> dict[str, Any]:
        snapshot_value = getattr(
            evidence,
            "snapshot_json",
            None,
        )

        if snapshot_value is None:
            snapshot_value = getattr(
                evidence,
                "snapshot",
                None,
            )

        snapshot = (
            InvestigatorService
            ._parse_json_value(
                snapshot_value,
                fallback_key=(
                    "raw_snapshot"
                ),
            )
        )

        return {
            "id": evidence.id,
            "incident_id": (
                evidence.incident_id
            ),
            "username": (
                evidence.username
            ),
            "evidence_type": (
                evidence.evidence_type
            ),
            "snapshot": snapshot,
            "sha256_hash": (
                evidence.sha256_hash
            ),
            "created_at": (
                evidence.created_at
            ),
        }

    @staticmethod
    def _serialize_timeline_event(
        event: IncidentEvent,
    ) -> dict[str, Any]:
        metadata = (
            InvestigatorService
            ._parse_json_value(
                event.event_metadata,
                fallback_key=(
                    "raw_metadata"
                ),
            )
        )

        return {
            "id": event.id,
            "incident_id": (
                event.incident_id
            ),
            "event_type": (
                event.event_type
            ),
            "actor_type": (
                event.actor_type
            ),
            "actor_name": (
                event.actor_name
            ),
            "description": (
                event.description
            ),
            "old_status": (
                event.old_status
            ),
            "new_status": (
                event.new_status
            ),
            "metadata": metadata,
            "created_at": (
                event.created_at
            ),
        }

    @staticmethod
    def _serialize_normalized_event(
        event: NormalizedWindowsEvent,
    ) -> dict[str, Any]:
        details = (
            InvestigatorService
            ._parse_json_value(
                event.details,
                fallback_key="raw_details",
            )
        )

        return {
            "id": event.id,
            "raw_event_id": (
                event.raw_event_id
            ),
            "event_id": (
                event.event_id
            ),
            "username": (
                event.username
            ),
            "source_ip": (
                event.source_ip
            ),
            "computer": (
                event.computer
            ),
            "action": (
                event.action
            ),
            "severity": (
                event.severity
            ),
            "details": details,
            "created_at": (
                event.created_at
            ),
        }

    @staticmethod
    def _normalize_chain_verification(
        result: dict[str, Any],
    ) -> dict[str, Any]:
        is_valid = bool(
            result.get(
                "is_valid",
                result.get(
                    "verified",
                    False,
                ),
            )
        )

        return {
            **result,
            "is_valid": is_valid,
            "verified": is_valid,
        }

    @staticmethod
    def _get_alert(
        db: Session,
        alert_id: int | None,
    ) -> Alert | None:
        if not alert_id:
            return None

        return (
            db.query(Alert)
            .filter(
                Alert.id == alert_id
            )
            .first()
        )

    @staticmethod
    def _get_timeline(
        db: Session,
        incident_id: int,
    ) -> list[IncidentEvent]:
        return (
            db.query(IncidentEvent)
            .filter(
                IncidentEvent.incident_id
                == incident_id
            )
            .order_by(
                IncidentEvent.created_at.asc()
            )
            .all()
        )

    @staticmethod
    def _get_related_normalized_events(
        db: Session,
        username: str,
        limit: int = 50,
    ) -> list[NormalizedWindowsEvent]:
        if not username:
            return []

        return (
            db.query(
                NormalizedWindowsEvent
            )
            .filter(
                NormalizedWindowsEvent.username
                == username
            )
            .order_by(
                NormalizedWindowsEvent
                .created_at
                .desc()
            )
            .limit(limit)
            .all()
        )

    @classmethod
    def _extract_indicators(
        cls,
        alert_data: dict[str, Any] | None,
        evidence_data: list[dict[str, Any]],
        timeline_data: list[dict[str, Any]],
        normalized_events: list[
            dict[str, Any]
        ],
    ) -> list[dict[str, Any]]:
        indicators: list[
            dict[str, Any]
        ] = []

        seen: set[str] = set()

        def add_indicator(
            indicator_type: str,
            value: Any,
            source: str,
        ) -> None:
            if value is None:
                return

            if (
                isinstance(value, str)
                and not value.strip()
            ):
                return

            if (
                isinstance(
                    value,
                    (
                        list,
                        tuple,
                        set,
                        dict,
                    ),
                )
                and not value
            ):
                return

            serializable_value = (
                cls._make_json_serializable(
                    value
                )
            )

            normalized_value = json.dumps(
                serializable_value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )

            key = (
                f"{indicator_type}:"
                f"{normalized_value}"
            )

            if key in seen:
                return

            seen.add(key)

            indicators.append(
                {
                    "type": indicator_type,
                    "value": (
                        serializable_value
                    ),
                    "source": source,
                }
            )

        interesting_keys = {
            "source_ip",
            "computer",
            "process_name",
            "process_path",
            "command_line",
            "parent_process_name",
            "dangerous_privileges",
            "privileges",
            "target_username",
            "actor_username",
            "member_username",
            "group_name",
            "target_domain",
            "group_domain",
            "failure_count",
            "logon_type",
            "risk_score",
            "severity",
        }

        for event in timeline_data:
            metadata = (
                event.get(
                    "metadata"
                )
                or {}
            )

            if isinstance(
                metadata,
                dict,
            ):
                for key in (
                    interesting_keys
                ):
                    add_indicator(
                        key,
                        metadata.get(key),
                        (
                            "incident_timeline:"
                            + str(
                                event.get(
                                    "event_type"
                                )
                            )
                        ),
                    )

        for event in normalized_events:
            add_indicator(
                "windows_event_id",
                event.get(
                    "event_id"
                ),
                "normalized_event",
            )

            add_indicator(
                "action",
                event.get("action"),
                "normalized_event",
            )

            add_indicator(
                "source_ip",
                event.get(
                    "source_ip"
                ),
                "normalized_event",
            )

            add_indicator(
                "computer",
                event.get(
                    "computer"
                ),
                "normalized_event",
            )

            details = (
                event.get(
                    "details"
                )
                or {}
            )

            if isinstance(
                details,
                dict,
            ):
                for key in (
                    interesting_keys
                ):
                    add_indicator(
                        key,
                        details.get(key),
                        "normalized_event",
                    )

        for evidence in evidence_data:
            snapshot = (
                evidence.get(
                    "snapshot"
                )
                or {}
            )

            if isinstance(
                snapshot,
                dict,
            ):
                for key in (
                    interesting_keys
                ):
                    add_indicator(
                        key,
                        snapshot.get(key),
                        "evidence",
                    )

        return indicators

    @classmethod
    def _extract_mitre_techniques(
        cls,
        alert_data: dict[str, Any] | None,
        timeline_data: list[dict[str, Any]],
        normalized_events: list[
            dict[str, Any]
        ],
    ) -> list[dict[str, Any]]:
        techniques: list[
            dict[str, Any]
        ] = []

        seen_ids: set[str] = set()

        def add_technique(
            value: Any,
        ) -> None:
            if not isinstance(
                value,
                dict,
            ):
                return

            technique_id = (
                value.get(
                    "technique_id"
                )
                or value.get(
                    "id"
                )
            )

            if not technique_id:
                return

            if technique_id in seen_ids:
                return

            seen_ids.add(
                technique_id
            )

            techniques.append(
                {
                    "technique_id": (
                        technique_id
                    ),
                    "technique_name": (
                        value.get(
                            "technique_name"
                        )
                        or value.get(
                            "name"
                        )
                        or "Unknown"
                    ),
                    "tactic": (
                        value.get(
                            "tactic"
                        )
                        or "Unknown"
                    ),
                }
            )

        for event in timeline_data:
            metadata = (
                event.get(
                    "metadata"
                )
                or {}
            )

            if isinstance(
                metadata,
                dict,
            ):
                mitre = metadata.get(
                    "mitre"
                )

                if isinstance(
                    mitre,
                    list,
                ):
                    for item in mitre:
                        add_technique(
                            item
                        )
                else:
                    add_technique(
                        mitre
                    )

            event_type = str(
                event.get(
                    "event_type"
                )
                or ""
            ).upper()

            for technique in (
                cls.EVENT_MITRE_MAP.get(
                    event_type,
                    [],
                )
            ):
                add_technique(
                    technique
                )

        for event in normalized_events:
            details = (
                event.get(
                    "details"
                )
                or {}
            )

            if isinstance(
                details,
                dict,
            ):
                mitre = details.get(
                    "mitre"
                )

                if isinstance(
                    mitre,
                    list,
                ):
                    for item in mitre:
                        add_technique(
                            item
                        )
                else:
                    add_technique(
                        mitre
                    )

            action = str(
                event.get(
                    "action"
                )
                or ""
            ).upper()

            for technique in (
                cls.EVENT_MITRE_MAP.get(
                    action,
                    [],
                )
            ):
                add_technique(
                    technique
                )

        if alert_data:
            alert_type = str(
                alert_data.get(
                    "alert_type"
                )
                or ""
            ).upper()

            for technique in (
                cls.EVENT_MITRE_MAP.get(
                    alert_type,
                    [],
                )
            ):
                add_technique(
                    technique
                )

        return techniques

    @classmethod
    def generate_report(
        cls,
        db: Session,
        incident_id: int,
        llm: LLMProvider | None = None,
    ) -> InvestigationReport:
        existing_report = (
            InvestigationRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if existing_report is not None:
            return existing_report

        incident = (
            IncidentRepository.get_by_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if incident is None:
            raise ValueError(
                "Incident not found"
            )

        evidences = (
            EvidenceRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if not evidences:
            raise ValueError(
                "No evidence found for this incident"
            )

        alert = cls._get_alert(
            db=db,
            alert_id=incident.alert_id,
        )

        timeline = cls._get_timeline(
            db=db,
            incident_id=incident_id,
        )

        normalized_events = (
            cls
            ._get_related_normalized_events(
                db=db,
                username=incident.username,
            )
        )

        chain_result = (
            BlockchainService.verify_chain(
                db=db
            )
        )

        chain_verification = (
            cls
            ._normalize_chain_verification(
                chain_result
            )
        )

        incident_data = (
            cls._serialize_incident(
                incident
            )
        )

        alert_data = (
            cls._serialize_alert(
                alert
            )
        )

        evidence_data = [
            cls._serialize_evidence(
                evidence
            )
            for evidence in evidences
        ]

        timeline_data = [
            cls._serialize_timeline_event(
                event
            )
            for event in timeline
        ]

        normalized_event_data = [
            cls
            ._serialize_normalized_event(
                event
            )
            for event
            in normalized_events
        ]

        indicators = (
            cls._extract_indicators(
                alert_data=alert_data,
                evidence_data=(
                    evidence_data
                ),
                timeline_data=(
                    timeline_data
                ),
                normalized_events=(
                    normalized_event_data
                ),
            )
        )

        mitre_techniques = (
            cls
            ._extract_mitre_techniques(
                alert_data=alert_data,
                timeline_data=(
                    timeline_data
                ),
                normalized_events=(
                    normalized_event_data
                ),
            )
        )

        investigation_context = {
            "incident": (
                incident_data
            ),
            "alert": alert_data,
            "risk_score": (
                alert_data.get(
                    "risk_score"
                )
                if alert_data
                else None
            ),
            "risk_level": (
                alert_data.get(
                    "severity"
                )
                if alert_data
                else incident.severity
            ),
            "evidences": (
                evidence_data
            ),
            "evidence": (
                evidence_data[0]
            ),
            "timeline": (
                timeline_data
            ),
            "normalized_events": (
                normalized_event_data
            ),
            "indicators": (
                indicators
            ),
            "mitre_techniques": (
                mitre_techniques
            ),
            "blockchain_verification": (
                chain_verification
            ),
        }

        # Giữ tương thích với PromptBuilder cũ,
        # đồng thời truyền thêm context mới.
        prompt = (
            InvestigationPromptBuilder.build(
                incident=incident_data,
                evidence=evidence_data[0],
                blockchain_verification=(
                    chain_verification
                ),
                alert=alert_data,
                timeline=timeline_data,
                indicators=indicators,
                mitre_techniques=(
                    mitre_techniques
                ),
            )
        )

        investigation_context[
            "prompt"
        ] = prompt

        provider = (
            llm
            or MockInvestigationLLM()
        )

        generated = (
            provider.generate_report(
                investigation_context
            )
        )

        recommendations = (
            generated.get(
                "recommendations",
                [],
            )
        )

        generated_mitre = (
            generated.get(
                "mitre_techniques",
                [],
            )
        )

        final_mitre = (
            generated_mitre
            or mitre_techniques
        )

        report = InvestigationReport(
            incident_id=incident_id,

            summary=generated.get(
                "summary",
                (
                    "No summary generated."
                ),
            ),

            analysis=generated.get(
                "analysis",
                (
                    "No analysis generated."
                ),
            ),

            recommendations=json.dumps(
                recommendations,
                ensure_ascii=False,
            ),

            mitre_techniques=json.dumps(
                final_mitre,
                ensure_ascii=False,
            ),

            confidence=float(
                generated.get(
                    "confidence",
                    0.0,
                )
            ),

            model_name=(
                provider.model_name
            ),

            prompt_snapshot=prompt,
        )

        try:
            return (
                InvestigationRepository
                .create(
                    db=db,
                    report=report,
                )
            )

        except Exception:
            db.rollback()
            raise

    @staticmethod
    def get_report(
        db: Session,
        report_id: int,
    ) -> InvestigationReport | None:
        return (
            InvestigationRepository
            .get_by_id(
                db=db,
                report_id=report_id,
            )
        )

    @staticmethod
    def get_incident_report(
        db: Session,
        incident_id: int,
    ) -> InvestigationReport | None:
        return (
            InvestigationRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

    @classmethod
    def regenerate_report(
        cls,
        db: Session,
        incident_id: int,
        llm: LLMProvider | None = None,
    ) -> InvestigationReport:
        existing_report = (
            InvestigationRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if existing_report is not None:
            InvestigationRepository.delete(
                db=db,
                report=existing_report,
            )

        return cls.generate_report(
            db=db,
            incident_id=incident_id,
            llm=llm,
        )
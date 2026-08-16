import hashlib
import json

from sqlalchemy.orm import (
    Session,
)

from app.models.evidence import (
    Evidence,
)

from app.modules.blockchain.service import (
    BlockchainService,
)


class EvidenceService:

    @staticmethod
    def _hash_snapshot(
        snapshot_text: str,
    ) -> str:

        return (
            hashlib.sha256(
                snapshot_text.encode(
                    "utf-8"
                )
            )
            .hexdigest()
        )

    @classmethod
    def create_snapshot(
        cls,
        db: Session,
        incident_id: int,
        username: str,
        snapshot: dict,
        evidence_type: str = (
            "INCIDENT_SNAPSHOT"
        ),
    ) -> Evidence:

        snapshot_text = (
            json.dumps(
                snapshot,
                sort_keys=True,
                default=str,
            )
        )

        sha256_hash = (
            cls._hash_snapshot(
                snapshot_text
            )
        )

        evidence = Evidence(
            incident_id=(
                incident_id
            ),

            username=(
                username
            ),

            evidence_type=(
                evidence_type
            ),

            snapshot_json=(
                snapshot_text
            ),

            sha256_hash=(
                sha256_hash
            ),
        )

        db.add(
            evidence
        )

        db.commit()

        db.refresh(
            evidence
        )

        BlockchainService.create_block(
            db=db,

            evidence_id=(
                evidence.id
            ),

            evidence_hash=(
                evidence.sha256_hash
            ),
        )

        return evidence

    @classmethod
    def create_from_incident(
        cls,
        db: Session,
        incident,
    ) -> Evidence:

        snapshot = {
            "snapshot_type":
                "INCIDENT_SNAPSHOT",

            "incident_id":
                incident.id,

            "alert_id":
                incident.alert_id,

            "username":
                incident.username,

            "title":
                incident.title,

            "severity":
                incident.severity,

            "status":
                incident.status,

            "description":
                incident.description,

            "created_at":
                incident.created_at,

            "closed_at":
                incident.closed_at,
        }

        return (
            cls.create_snapshot(
                db=db,

                incident_id=(
                    incident.id
                ),

                username=(
                    incident.username
                    or "UNKNOWN"
                ),

                snapshot=(
                    snapshot
                ),

                evidence_type=(
                    "INCIDENT_SNAPSHOT"
                ),
            )
        )

    @classmethod
    def create_correlation_snapshot(
        cls,
        db: Session,
        *,
        incident_id: int,
        username: str,
        correlation,
    ) -> Evidence:

        snapshot = {
            "snapshot_type":
                "CORRELATION_SNAPSHOT",

            "incident_id":
                incident_id,

            "username":
                username,

            "detected":
                correlation.detected,

            "score":
                correlation.score,

            "severity":
                correlation.severity,

            "computer":
                correlation.computer,

            "process_guid":
                correlation.process_guid,

            "process_id":
                correlation.process_id,

            "process_image":
                correlation.process_image,

            "parent_process_guid":
                correlation
                .parent_process_guid,

            "parent_process_id":
                correlation
                .parent_process_id,

            "parent_image":
                correlation.parent_image,

            "process_chain":
                correlation.process_chain,

            "related_process_guids":
                correlation
                .related_process_guids,

            "event_ids":
                correlation.event_ids,

            "mitre_techniques":
                correlation
                .mitre_techniques,

            "reasons":
                correlation.reasons,

            "events":
                correlation.events,

            "usb_events":
                correlation.usb_events,

            "usb_file_transfers":
                correlation
                .usb_file_transfers,
        }

        return (
            cls.create_snapshot(
                db=db,

                incident_id=(
                    incident_id
                ),

                username=(
                    username
                    or "UNKNOWN"
                ),

                snapshot=(
                    snapshot
                ),

                evidence_type=(
                    "CORRELATION_SNAPSHOT"
                ),
            )
        )

    @staticmethod
    def get_evidence(
        db: Session,
        evidence_id: int,
    ) -> Evidence | None:

        return (
            db.query(
                Evidence
            )
            .filter(
                Evidence.id
                == evidence_id
            )
            .first()
        )

    @staticmethod
    def get_incident_evidence(
        db: Session,
        incident_id: int,
    ) -> list[Evidence]:

        return (
            db.query(
                Evidence
            )
            .filter(
                Evidence.incident_id
                == incident_id
            )
            .order_by(
                Evidence.created_at
                .desc()
            )
            .all()
        )

    @classmethod
    def verify_evidence(
        cls,
        evidence: Evidence,
    ) -> tuple[
        str,
        bool,
    ]:

        calculated_hash = (
            cls._hash_snapshot(
                evidence.snapshot_json
            )
        )

        return (
            calculated_hash,

            calculated_hash
            == evidence.sha256_hash,
        )
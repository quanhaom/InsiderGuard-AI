import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.blockchain_block import BlockchainBlock
from app.models.evidence import Evidence
from app.models.incident import Incident


class CaseExplorerService:

    @staticmethod
    def _parse_snapshot(
        snapshot_json: str
    ) -> dict[str, Any]:
        try:
            parsed = json.loads(snapshot_json)

            if isinstance(parsed, dict):
                return parsed

            return {
                "value": parsed
            }

        except (
            json.JSONDecodeError,
            TypeError,
        ):
            return {
                "raw_snapshot": snapshot_json
            }

    @classmethod
    def list_incidents(
        cls,
        db: Session,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        severity: str | None = None,
        username: str | None = None,
    ) -> dict[str, Any]:

        query = db.query(Incident)

        if status:
            query = query.filter(
                Incident.status == status.upper()
            )

        if severity:
            query = query.filter(
                Incident.severity == severity.upper()
            )

        if username:
            query = query.filter(
                Incident.username.ilike(
                    f"%{username.strip()}%"
                )
            )

        total = query.count()

        incidents = (
            query
            .order_by(
                Incident.created_at.desc(),
                Incident.id.desc(),
            )
            .offset(
                (page - 1) * page_size
            )
            .limit(page_size)
            .all()
        )

        total_pages = (
            total + page_size - 1
        ) // page_size

        return {
            "items": [
                {
                    "id": incident.id,
                    "alert_id": incident.alert_id,
                    "username": incident.username,
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                    "description": incident.description,
                    "created_at": incident.created_at,
                    "closed_at": incident.closed_at,
                }
                for incident in incidents
            ],
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        }

    @classmethod
    def get_incident(
        cls,
        db: Session,
        incident_id: int,
    ) -> dict[str, Any] | None:

        incident = (
            db.query(Incident)
            .filter(
                Incident.id == incident_id
            )
            .first()
        )

        if incident is None:
            return None

        alert = (
            db.query(Alert)
            .filter(
                Alert.id == incident.alert_id
            )
            .first()
        )

        evidences = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id == incident.id
            )
            .order_by(
                Evidence.created_at.desc()
            )
            .all()
        )

        return {
            "id": incident.id,
            "alert_id": incident.alert_id,
            "username": incident.username,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "description": incident.description,
            "created_at": incident.created_at,
            "closed_at": incident.closed_at,

            "alert": (
                {
                    "id": alert.id,
                    "username": alert.username,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "reason": alert.reason,
                    "created_at": alert.created_at,
                }
                if alert
                else None
            ),

            "evidences": [
                {
                    "id": evidence.id,
                    "incident_id": evidence.incident_id,
                    "username": evidence.username,
                    "evidence_type": evidence.evidence_type,
                    "sha256_hash": evidence.sha256_hash,
                    "created_at": evidence.created_at,
                }
                for evidence in evidences
            ],
        }

    @classmethod
    def list_evidences(
        cls,
        db: Session,
        *,
        page: int = 1,
        page_size: int = 20,
        incident_id: int | None = None,
        username: str | None = None,
        evidence_type: str | None = None,
    ) -> dict[str, Any]:

        query = db.query(Evidence)

        if incident_id is not None:
            query = query.filter(
                Evidence.incident_id == incident_id
            )

        if username:
            query = query.filter(
                Evidence.username.ilike(
                    f"%{username.strip()}%"
                )
            )

        if evidence_type:
            query = query.filter(
                Evidence.evidence_type.ilike(
                    f"%{evidence_type.strip()}%"
                )
            )

        total = query.count()

        evidences = (
            query
            .order_by(
                Evidence.created_at.desc(),
                Evidence.id.desc(),
            )
            .offset(
                (page - 1) * page_size
            )
            .limit(page_size)
            .all()
        )

        total_pages = (
            total + page_size - 1
        ) // page_size

        return {
            "items": [
                {
                    "id": evidence.id,
                    "incident_id": evidence.incident_id,
                    "username": evidence.username,
                    "evidence_type": evidence.evidence_type,
                    "sha256_hash": evidence.sha256_hash,
                    "created_at": evidence.created_at,
                }
                for evidence in evidences
            ],
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        }

    @classmethod
    def get_evidence(
        cls,
        db: Session,
        evidence_id: int,
    ) -> dict[str, Any] | None:

        evidence = (
            db.query(Evidence)
            .filter(
                Evidence.id == evidence_id
            )
            .first()
        )

        if evidence is None:
            return None

        incident = (
            db.query(Incident)
            .filter(
                Incident.id == evidence.incident_id
            )
            .first()
        )

        blockchain_block = (
            db.query(BlockchainBlock)
            .filter(
                BlockchainBlock.evidence_id
                == evidence.id
            )
            .first()
        )

        return {
            "id": evidence.id,
            "incident_id": evidence.incident_id,
            "username": evidence.username,
            "evidence_type": evidence.evidence_type,
            "snapshot": cls._parse_snapshot(
                evidence.snapshot_json
            ),
            "snapshot_json": evidence.snapshot_json,
            "sha256_hash": evidence.sha256_hash,
            "created_at": evidence.created_at,

            "incident": (
                {
                    "id": incident.id,
                    "title": incident.title,
                    "username": incident.username,
                    "severity": incident.severity,
                    "status": incident.status,
                }
                if incident
                else None
            ),

            "blockchain": (
                {
                    "id": blockchain_block.id,
                    "block_index": (
                        blockchain_block.block_index
                    ),
                    "evidence_id": (
                        blockchain_block.evidence_id
                    ),
                    "evidence_hash": (
                        blockchain_block.evidence_hash
                    ),
                    "previous_hash": (
                        blockchain_block.previous_hash
                    ),
                    "block_hash": (
                        blockchain_block.block_hash
                    ),
                    "nonce": blockchain_block.nonce,
                    "created_at": (
                        blockchain_block.created_at
                    ),
                    "is_hash_matching": (
                        blockchain_block.evidence_hash
                        == evidence.sha256_hash
                    ),
                }
                if blockchain_block
                else None
            ),
        }
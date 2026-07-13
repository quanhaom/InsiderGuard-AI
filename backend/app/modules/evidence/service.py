import hashlib
import json

from sqlalchemy.orm import Session
from app.modules.blockchain.service import BlockchainService
from app.models.evidence import Evidence


class EvidenceService:


    @staticmethod
    def create_snapshot(
        db: Session,
        incident_id: int,
        username: str,
        snapshot: dict
    ) -> Evidence:


        snapshot_text = json.dumps(
            snapshot,
            sort_keys=True,
            default=str
        )


        sha256_hash = hashlib.sha256(
            snapshot_text.encode(
                "utf-8"
            )
        ).hexdigest()


        evidence = Evidence(

            incident_id=incident_id,

            username=username,

            evidence_type="INCIDENT_SNAPSHOT",

            snapshot_json=snapshot_text,

            sha256_hash=sha256_hash
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
            evidence_hash=evidence.sha256_hash
)

        return evidence
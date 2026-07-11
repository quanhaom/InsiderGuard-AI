import hashlib
import json
from datetime import datetime
from typing import Any


class BlockchainHashService:

    @staticmethod
    def normalize_block_data(
        *,
        block_index: int,
        evidence_id: int,
        evidence_hash: str,
        previous_hash: str,
        nonce: int,
        created_at: datetime
    ) -> str:

        block_data: dict[str, Any] = {
            "block_index": block_index,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash,
            "nonce": nonce,
            "created_at": created_at.isoformat()
        }

        return json.dumps(
            block_data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":")
        )

    @classmethod
    def generate_block_hash(
        cls,
        *,
        block_index: int,
        evidence_id: int,
        evidence_hash: str,
        previous_hash: str,
        nonce: int,
        created_at: datetime
    ) -> str:

        normalized = cls.normalize_block_data(
            block_index=block_index,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            previous_hash=previous_hash,
            nonce=nonce,
            created_at=created_at
        )

        return hashlib.sha256(
            normalized.encode("utf-8")
        ).hexdigest()
import hashlib
import json
from typing import Any


class EvidenceHashService:

    @staticmethod
    def normalize_snapshot(
        snapshot: dict[str, Any]
    ) -> str:
        return json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str
        )

    @classmethod
    def generate_hash(
        cls,
        snapshot: dict[str, Any]
    ) -> str:
        normalized = cls.normalize_snapshot(snapshot)

        return hashlib.sha256(
            normalized.encode("utf-8")
        ).hexdigest()

    @classmethod
    def verify_hash(
        cls,
        snapshot: dict[str, Any],
        expected_hash: str
    ) -> bool:
        calculated_hash = cls.generate_hash(snapshot)

        return calculated_hash == expected_hash
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.blockchain_block import BlockchainBlock
from app.models.evidence import Evidence
from app.modules.blockchain.hash_service import (
    BlockchainHashService,
)
from app.modules.evidence.hash_service import EvidenceHashService
from app.repositories.blockchain_repository import (
    BlockchainRepository,
)
from app.repositories.evidence_repository import EvidenceRepository


class BlockchainService:

    GENESIS_PREVIOUS_HASH = "0" * 64

    @classmethod
    def add_evidence(
        cls,
        db: Session,
        evidence: Evidence
    ) -> BlockchainBlock:
        existing_block = (
            BlockchainRepository.get_by_evidence_id(
                db=db,
                evidence_id=evidence.id
            )
        )

        if existing_block is not None:
            return existing_block

        latest_block = BlockchainRepository.get_latest(db=db)

        if latest_block is None:
            block_index = 0
            previous_hash = cls.GENESIS_PREVIOUS_HASH
        else:
            block_index = latest_block.block_index + 1
            previous_hash = latest_block.block_hash

        created_at = datetime.utcnow()
        nonce = 0

        block_hash = BlockchainHashService.generate_block_hash(
            block_index=block_index,
            evidence_id=evidence.id,
            evidence_hash=evidence.sha256_hash,
            previous_hash=previous_hash,
            nonce=nonce,
            created_at=created_at
        )

        block = BlockchainBlock(
            block_index=block_index,
            evidence_id=evidence.id,
            evidence_hash=evidence.sha256_hash,
            previous_hash=previous_hash,
            block_hash=block_hash,
            nonce=nonce,
            created_at=created_at
        )

        return BlockchainRepository.create(
            db=db,
            block=block
        )

    @staticmethod
    def get_block(
        db: Session,
        block_id: int
    ) -> BlockchainBlock | None:
        return BlockchainRepository.get_by_id(
            db=db,
            block_id=block_id
        )

    @staticmethod
    def get_chain(
        db: Session
    ) -> list[BlockchainBlock]:
        return BlockchainRepository.get_all(db=db)

    @classmethod
    def verify_block(
        cls,
        db: Session,
        block: BlockchainBlock,
        previous_block: BlockchainBlock | None
    ) -> dict:
        evidence = EvidenceRepository.get_by_id(
            db=db,
            evidence_id=block.evidence_id
        )

        evidence_valid = False

        if evidence is not None:
            try:
                import json

                snapshot = json.loads(evidence.snapshot_json)

                calculated_evidence_hash = (
                    EvidenceHashService.generate_hash(snapshot)
                )

                evidence_valid = (
                    calculated_evidence_hash
                    == evidence.sha256_hash
                    == block.evidence_hash
                )
            except (json.JSONDecodeError, TypeError):
                evidence_valid = False

        calculated_block_hash = (
            BlockchainHashService.generate_block_hash(
                block_index=block.block_index,
                evidence_id=block.evidence_id,
                evidence_hash=block.evidence_hash,
                previous_hash=block.previous_hash,
                nonce=block.nonce,
                created_at=block.created_at
            )
        )

        block_hash_valid = (
            calculated_block_hash == block.block_hash
        )

        if previous_block is None:
            previous_hash_valid = (
                block.block_index == 0
                and block.previous_hash
                == cls.GENESIS_PREVIOUS_HASH
            )
        else:
            previous_hash_valid = (
                block.previous_hash
                == previous_block.block_hash
            )

        is_valid = (
            evidence_valid
            and block_hash_valid
            and previous_hash_valid
        )

        return {
            "block_id": block.id,
            "block_index": block.block_index,
            "evidence_valid": evidence_valid,
            "block_hash_valid": block_hash_valid,
            "previous_hash_valid": previous_hash_valid,
            "is_valid": is_valid
        }

    @classmethod
    def verify_chain(
        cls,
        db: Session
    ) -> dict:
        blocks = BlockchainRepository.get_all(db=db)

        results: list[dict] = []
        previous_block = None

        for block in blocks:
            result = cls.verify_block(
                db=db,
                block=block,
                previous_block=previous_block
            )

            results.append(result)
            previous_block = block

        valid_blocks = sum(
            1 for result in results
            if result["is_valid"]
        )

        invalid_blocks = len(results) - valid_blocks

        return {
            "total_blocks": len(blocks),
            "valid_blocks": valid_blocks,
            "invalid_blocks": invalid_blocks,
            "is_valid": invalid_blocks == 0,
            "results": results
        }
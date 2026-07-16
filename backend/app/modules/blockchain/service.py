from datetime import datetime

from sqlalchemy.orm import Session

from app.models.blockchain_block import BlockchainBlock
from app.models.evidence import Evidence

from app.modules.blockchain.hash_service import (
    BlockchainHashService,
)
from app.modules.incidents.timeline_service import (
    IncidentTimelineService,
)


class BlockchainService:

    @staticmethod
    def create_block(
        db: Session,
        evidence_id: int,
        evidence_hash: str,
    ) -> BlockchainBlock:
        existing_block = (
            db.query(BlockchainBlock)
            .filter(
                BlockchainBlock.evidence_id
                == evidence_id
            )
            .first()
        )

        if existing_block is not None:
            return existing_block

        last_block = (
            db.query(BlockchainBlock)
            .order_by(
                BlockchainBlock.block_index.desc()
            )
            .first()
        )

        if last_block is not None:
            previous_hash = (
                last_block.block_hash
            )
            block_index = (
                last_block.block_index + 1
            )
        else:
            previous_hash = "0"
            block_index = 1

        nonce = 0
        created_at = datetime.utcnow()

        block_hash = (
            BlockchainHashService
            .generate_block_hash(
                block_index=block_index,
                evidence_id=evidence_id,
                evidence_hash=evidence_hash,
                previous_hash=previous_hash,
                nonce=nonce,
                created_at=created_at,
            )
        )

        block = BlockchainBlock(
            block_index=block_index,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            previous_hash=previous_hash,
            block_hash=block_hash,
            nonce=nonce,
            created_at=created_at,
        )

        db.add(block)
        db.commit()
        db.refresh(block)

        evidence = (
            db.query(Evidence)
            .filter(
                Evidence.id == evidence_id
            )
            .first()
        )

        if evidence is not None:
            IncidentTimelineService.create_event(
                db=db,
                incident_id=evidence.incident_id,
                event_type="BLOCKCHAIN_SEALED",
                actor_type="SYSTEM",
                description=(
                    "Evidence hash sealed "
                    "into blockchain"
                ),
                event_metadata={
                    "evidence_id": evidence.id,
                    "block_id": block.id,
                    "block_index": (
                        block.block_index
                    ),
                    "block_hash": (
                        block.block_hash
                    ),
                },
            )

        return block

    @staticmethod
    def verify_chain(
        db: Session,
    ) -> dict:
        blocks = (
            db.query(BlockchainBlock)
            .order_by(
                BlockchainBlock.block_index.asc()
            )
            .all()
        )

        if not blocks:
            return {
                "total_blocks": 0,
                "valid_blocks": 0,
                "invalid_blocks": 0,
                "is_valid": False,
                "results": [],
            }

        previous_hash = "0"
        results: list[dict] = []

        valid_blocks = 0
        invalid_blocks = 0

        for block in blocks:
            calculated_hash = (
                BlockchainHashService
                .generate_block_hash(
                    block_index=(
                        block.block_index
                    ),
                    evidence_id=(
                        block.evidence_id
                    ),
                    evidence_hash=(
                        block.evidence_hash
                    ),
                    previous_hash=(
                        block.previous_hash
                    ),
                    nonce=block.nonce,
                    created_at=(
                        block.created_at
                    ),
                )
            )

            block_hash_valid = (
                calculated_hash
                == block.block_hash
            )

            previous_hash_valid = (
                block.previous_hash
                == previous_hash
            )

            evidence = (
                db.query(Evidence)
                .filter(
                    Evidence.id
                    == block.evidence_id
                )
                .first()
            )

            evidence_valid = (
                evidence is not None
                and evidence.sha256_hash
                == block.evidence_hash
            )

            is_valid = (
                evidence_valid
                and block_hash_valid
                and previous_hash_valid
            )

            if is_valid:
                valid_blocks += 1
            else:
                invalid_blocks += 1

            results.append(
                {
                    "block_id": block.id,
                    "block_index": (
                        block.block_index
                    ),
                    "evidence_id": (
                        block.evidence_id
                    ),
                    "evidence_valid": (
                        evidence_valid
                    ),
                    "block_hash_valid": (
                        block_hash_valid
                    ),
                    "previous_hash_valid": (
                        previous_hash_valid
                    ),
                    "is_valid": is_valid,
                    "stored_hash": (
                        block.block_hash
                    ),
                    "calculated_hash": (
                        calculated_hash
                    ),
                }
            )

            previous_hash = block.block_hash

        return {
            "total_blocks": len(blocks),
            "valid_blocks": valid_blocks,
            "invalid_blocks": invalid_blocks,
            "is_valid": (
                invalid_blocks == 0
            ),
            "results": results,
        }
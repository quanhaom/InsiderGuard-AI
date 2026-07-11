from sqlalchemy.orm import Session

from app.models.blockchain_block import BlockchainBlock


class BlockchainRepository:

    @staticmethod
    def create(
        db: Session,
        block: BlockchainBlock
    ) -> BlockchainBlock:
        db.add(block)
        db.commit()
        db.refresh(block)

        return block

    @staticmethod
    def get_by_id(
        db: Session,
        block_id: int
    ) -> BlockchainBlock | None:
        return (
            db.query(BlockchainBlock)
            .filter(BlockchainBlock.id == block_id)
            .first()
        )

    @staticmethod
    def get_by_evidence_id(
        db: Session,
        evidence_id: int
    ) -> BlockchainBlock | None:
        return (
            db.query(BlockchainBlock)
            .filter(
                BlockchainBlock.evidence_id == evidence_id
            )
            .first()
        )

    @staticmethod
    def get_latest(
        db: Session
    ) -> BlockchainBlock | None:
        return (
            db.query(BlockchainBlock)
            .order_by(BlockchainBlock.block_index.desc())
            .first()
        )

    @staticmethod
    def get_all(
        db: Session
    ) -> list[BlockchainBlock]:
        return (
            db.query(BlockchainBlock)
            .order_by(BlockchainBlock.block_index.asc())
            .all()
        )
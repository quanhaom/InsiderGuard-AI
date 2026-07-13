from datetime import datetime

from sqlalchemy.orm import Session

from app.models.blockchain_block import BlockchainBlock

from app.modules.blockchain.hash_service import (
    BlockchainHashService
)


class BlockchainService:


    @staticmethod
    def create_block(
        db: Session,
        evidence_id: int,
        evidence_hash: str
    ) -> BlockchainBlock:


        last_block = (
            db.query(BlockchainBlock)
            .order_by(
                BlockchainBlock.block_index.desc()
            )
            .first()
        )


        if last_block:

            previous_hash = last_block.block_hash

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

                created_at=created_at
            )
        )



        block = BlockchainBlock(

            block_index=block_index,

            evidence_id=evidence_id,

            evidence_hash=evidence_hash,

            previous_hash=previous_hash,

            block_hash=block_hash,

            nonce=nonce,

            created_at=created_at
        )


        db.add(block)

        db.commit()

        db.refresh(block)


        return block





    @staticmethod
    def verify_chain(
        db: Session
    ) -> dict:


        blocks = (

            db.query(BlockchainBlock)

            .order_by(
                BlockchainBlock.block_index
            )

            .all()

        )



        if not blocks:

            return {

                "verified": False,

                "message":
                "No blockchain records found"

            }



        previous_hash = "0"



        for block in blocks:



            calculated_hash = (

                BlockchainHashService
                .generate_block_hash(

                    block_index=
                    block.block_index,

                    evidence_id=
                    block.evidence_id,

                    evidence_hash=
                    block.evidence_hash,

                    previous_hash=
                    block.previous_hash,

                    nonce=
                    block.nonce,

                    created_at=
                    block.created_at

                )

            )



            if calculated_hash != block.block_hash:


                return {

                    "verified": False,

                    "message":
                    f"Invalid block {block.block_index}"

                }




            if block.previous_hash != previous_hash:


                return {

                    "verified": False,

                    "message":
                    f"Broken chain at block {block.block_index}"

                }



            previous_hash = block.block_hash




        return {

            "verified": True,

            "blocks": len(blocks),

            "integrity": "VALID"

        }
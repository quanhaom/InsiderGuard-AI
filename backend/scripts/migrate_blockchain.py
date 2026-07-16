from app.db.session import SessionLocal

from app.models.evidence import Evidence
from app.models.blockchain_block import BlockchainBlock

from app.modules.blockchain.service import BlockchainService



def migrate():

    db = SessionLocal()


    try:

        evidences = (
            db.query(Evidence)
            .order_by(
                Evidence.id.asc()
            )
            .all()
        )


        created = 0

        skipped = 0



        for evidence in evidences:


            existing = (
                db.query(BlockchainBlock)
                .filter(
                    BlockchainBlock.evidence_id
                    == evidence.id
                )
                .first()
            )


            if existing:

                print(
                    f"Skip Evidence #{evidence.id} "
                    "- blockchain already exists"
                )

                skipped += 1

                continue



            BlockchainService.create_block(

                db=db,

                evidence_id=evidence.id,

                evidence_hash=evidence.sha256_hash

            )


            print(
                f"Created block for Evidence #{evidence.id}"
            )


            created += 1



        print(
            "\nMigration completed"
        )


        print(
            f"Created blocks: {created}"
        )


        print(
            f"Skipped: {skipped}"
        )


    finally:

        db.close()



if __name__ == "__main__":

    migrate()
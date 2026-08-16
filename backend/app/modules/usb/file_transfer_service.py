from sqlalchemy.orm import Session

from app.models.usb_file_transfer import (
    UsbFileTransfer,
)

from app.schemas.usb_file_transfer import (
    UsbFileTransferCreate,
)

from app.modules.usb.detector import (
    UsbFileTransferDetector,
)


class UsbFileTransferService:

    @classmethod
    def create(
        cls,
        db: Session,
        payload: UsbFileTransferCreate,
    ) -> UsbFileTransfer:

        detection = (
            UsbFileTransferDetector
            .evaluate(
                extension=(
                    payload.extension
                ),
                file_size=(
                    payload.file_size
                ),
            )
        )

        transfer = UsbFileTransfer(
            computer=payload.computer,

            username=payload.username,

            device_id=payload.device_id,

            drive_letter=(
                payload.drive_letter
            ),

            file_path=payload.file_path,

            file_name=payload.file_name,

            extension=payload.extension,

            file_size=payload.file_size,

            sha256_hash=(
                payload.sha256_hash
            ),

            risk_score=(
                detection[
                    "risk_score"
                ]
            ),

            severity=(
                detection[
                    "severity"
                ]
            ),
        )

        db.add(
            transfer
        )

        db.commit()

        db.refresh(
            transfer
        )

        return transfer

    @staticmethod
    def get_recent(
        db: Session,
        *,
        computer: str | None = None,
        limit: int = 100,
    ) -> list[
        UsbFileTransfer
    ]:

        query = db.query(
            UsbFileTransfer
        )

        if computer:
            query = query.filter(
                UsbFileTransfer.computer
                == computer
            )

        return (
            query
            .order_by(
                UsbFileTransfer
                .created_at
                .desc()
            )
            .limit(limit)
            .all()
        )
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from sqlalchemy.orm import Session
from app.schemas.usb_file_transfer import (
    UsbFileTransferCreate,
    UsbFileTransferResponse,
)

from app.modules.usb.file_transfer_service import (
    UsbFileTransferService,
)
from app.db.dependencies import (
    get_db,
)

from app.schemas.usb_event import (
    UsbEventCreate,
    UsbEventResponse,
)

from app.modules.usb.service import (
    UsbService,
)


router = APIRouter(
    prefix="/usb",
    tags=["USB"],
)


@router.post(
    "/events",
    response_model=UsbEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_usb_event(
    payload: UsbEventCreate,
    db: Session = Depends(
        get_db
    ),
):
    try:
        return (
            UsbService
            .create_event(
                db=db,
                payload=payload,
            )
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

@router.post(
    "/file-transfers",
    response_model=(
        UsbFileTransferResponse
    ),
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def create_usb_file_transfer(
    payload: UsbFileTransferCreate,
    db: Session = Depends(
        get_db
    ),
):
    return (
        UsbFileTransferService
        .create(
            db=db,
            payload=payload,
        )
    )


@router.get(
    "/file-transfers",
    response_model=list[
        UsbFileTransferResponse
    ],
)
def get_usb_file_transfers(
    computer: str | None = Query(
        default=None,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
    db: Session = Depends(
        get_db
    ),
):
    return (
        UsbFileTransferService
        .get_recent(
            db=db,
            computer=computer,
            limit=limit,
        )
    )



@router.get(
    "/events",
    response_model=list[
        UsbEventResponse
    ],
)
def get_usb_events(
    computer: str | None = Query(
        default=None,
    ),
    event_type: str | None = Query(
        default=None,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
    db: Session = Depends(
        get_db
    ),
):
    return (
        UsbService
        .get_events(
            db=db,
            computer=computer,
            event_type=event_type,
            limit=limit,
        )
    )
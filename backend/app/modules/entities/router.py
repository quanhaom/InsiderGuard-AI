from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.entities.service import (
    EntityService,
)


router = APIRouter(
    prefix="/entities",
    tags=["Entities"],
)


# =========================================
# USERS
# =========================================

@router.get("/users")
def list_users(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    search: str | None = Query(
        default=None,
    ),
    department: str | None = Query(
        default=None,
    ),
    role: str | None = Query(
        default=None,
    ),
    db: Session = Depends(get_db),
):
    return EntityService.list_users(
        db=db,
        page=page,
        page_size=page_size,
        search=search,
        department=department,
        role=role,
    )


@router.get("/users/{user_id}")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
):
    user = EntityService.get_user(
        db=db,
        user_id=user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


# =========================================
# DEVICES
# =========================================

@router.get("/devices")
def list_devices(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    status_filter: str | None = Query(
        default=None,
        alias="status",
    ),
    owner_username: str | None = Query(
        default=None,
    ),
    search: str | None = Query(
        default=None,
    ),
    db: Session = Depends(get_db),
):
    return EntityService.list_devices(
        db=db,
        page=page,
        page_size=page_size,
        status=status_filter,
        owner_username=owner_username,
        search=search,
    )


@router.get("/devices/{device_id}")
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = EntityService.get_device(
        db=db,
        device_id=device_id,
    )

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    return device
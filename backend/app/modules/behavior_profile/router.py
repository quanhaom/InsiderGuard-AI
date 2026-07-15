from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.behavior_profile.service import (
    BehaviorProfileService,
)


router = APIRouter(
    prefix="/behavior-profile",
    tags=["Behavior Profile"],
)


@router.post("/build/{username}")
def build_profile(
    username: str,
    db: Session = Depends(get_db),
):
    try:
        profile = (
            BehaviorProfileService
            .build_profile(
                db=db,
                username=username,
            )
        )

        return {
            "status": "success",
            "profile": (
                BehaviorProfileService
                .serialize(profile)
            ),
        }

    except ValueError as exc:
        db.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=str(exc),
        ) from exc

    except Exception:
        db.rollback()
        raise


@router.get("/{username}")
def get_profile(
    username: str,
    db: Session = Depends(get_db),
):
    profile = (
        BehaviorProfileService
        .get_profile(
            db=db,
            username=username,
        )
    )

    if profile is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Behavior profile not found"
            ),
        )

    return (
        BehaviorProfileService
        .serialize(profile)
    )
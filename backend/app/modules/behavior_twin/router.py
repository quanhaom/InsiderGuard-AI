from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.behavior_twin.service import BehaviorTwinService
from app.schemas.behavior_profile import BehaviorProfileResponse


router = APIRouter(
    prefix="/behavior-twin",
    tags=["Behavior Twin"]
)


@router.post(
    "/build/{username}",
    response_model=BehaviorProfileResponse,
    status_code=status.HTTP_200_OK
)
def build_behavior_profile(
    username: str,
    db: Session = Depends(get_db)
):
    profile = BehaviorTwinService.build_profile(
        db=db,
        username=username
    )

    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No login events found for user '{username}'"
        )

    return profile


@router.get(
    "/{username}",
    response_model=BehaviorProfileResponse
)
def get_behavior_profile(
    username: str,
    db: Session = Depends(get_db)
):
    profile = BehaviorTwinService.get_profile(
        db=db,
        username=username
    )

    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Behavior profile for '{username}' not found"
        )

    return profile
from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from app.db.dependencies import get_db

from app.schemas.login_event import (
    LoginEventCreate
)

from app.modules.events.service import (
    EventService
)

router = APIRouter(
    prefix="/events",
    tags=["Events"]
)


@router.post("/login")
def create_login_event(
    payload: LoginEventCreate,
    db: Session = Depends(get_db)
):

    event = EventService.create_login_event(
        db,
        payload
    )

    return {
        "id": event.id,
        "username": event.username
    }
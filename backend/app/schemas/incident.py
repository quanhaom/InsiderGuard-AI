from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentResponse(BaseModel):

    id: int

    alert_id: int

    username: str

    title: str

    severity: str

    status: str

    description: str | None = None

    created_at: datetime

    closed_at: datetime | None = None


    model_config = ConfigDict(
        from_attributes=True
    )

class IncidentStatusUpdate(BaseModel):
    status: str
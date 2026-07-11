from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    risk_assessment_id: int
    title: str
    severity: str
    description: str
    status: str
    detected_at: datetime
    resolved_at: datetime | None


class IncidentStatusUpdate(BaseModel):
    status: str
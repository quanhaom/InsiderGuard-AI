from datetime import datetime

from pydantic import BaseModel


class InvestigationReportResponse(BaseModel):
    id: int
    incident_id: int
    summary: str
    analysis: str
    recommendations: list[str]
    mitre_techniques: list[str]
    confidence: float
    model_name: str
    created_at: datetime
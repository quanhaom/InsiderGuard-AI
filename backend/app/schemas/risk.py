from datetime import datetime

from pydantic import BaseModel


class LoginRiskEvaluationRequest(BaseModel):
    source_ip: str
    login_time: datetime


class RiskAssessmentResponse(BaseModel):
    id: int
    username: str
    risk_score: int
    risk_level: str
    reasons: list[str]
    created_at: datetime
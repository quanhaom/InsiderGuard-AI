from datetime import datetime
from typing import Any

from pydantic import BaseModel


class EvidenceResponse(BaseModel):
    id: int
    incident_id: int
    username: str
    evidence_type: str
    snapshot: dict[str, Any]
    sha256_hash: str
    created_at: datetime


class EvidenceVerificationResponse(BaseModel):
    evidence_id: int
    stored_hash: str
    calculated_hash: str
    is_valid: bool
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class BehaviorProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    avg_login_hour: float
    total_logins: int
    common_source_ip: str | None
    first_login_at: datetime | None
    last_login_at: datetime | None
    last_updated: datetime
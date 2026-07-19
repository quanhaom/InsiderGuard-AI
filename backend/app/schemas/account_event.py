from datetime import datetime

from pydantic import BaseModel


class AccountCreatedEventCreate(BaseModel):
    actor_username: str

    target_username: str

    target_domain: str | None = None

    target_sid: str | None = None

    source_ip: str | None = None

    computer: str

    event_time: datetime
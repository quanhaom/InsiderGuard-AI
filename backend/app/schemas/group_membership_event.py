from datetime import datetime

from pydantic import BaseModel


class GroupMembershipEventCreate(BaseModel):
    actor_username: str

    member_username: str

    member_sid: str | None = None

    group_name: str

    group_domain: str | None = None

    group_sid: str | None = None

    source_ip: str | None = None

    computer: str

    event_time: datetime
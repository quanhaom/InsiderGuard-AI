from datetime import datetime

from pydantic import BaseModel


class GroupMembershipEventCreate(
    BaseModel
):
    actor_username: str

    member_username: str

    group_name: str

    source_ip: str | None = None

    computer: str

    event_time: datetime
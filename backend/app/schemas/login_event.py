from datetime import datetime

from pydantic import BaseModel


class LoginEventCreate(BaseModel):

    username: str

    source_ip: str

    login_time: datetime
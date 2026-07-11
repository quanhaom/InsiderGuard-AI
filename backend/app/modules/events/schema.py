# schema.py

from pydantic import BaseModel
from datetime import datetime

class LoginEvent(BaseModel):
    username: str
    source_ip: str
    login_time: datetime
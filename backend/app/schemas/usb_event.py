from datetime import datetime

from pydantic import BaseModel


class UsbEventCreate(BaseModel):
    computer: str

    username: str | None = None

    event_type: str

    device_id: str | None = None

    drive_letter: str | None = None

    volume_label: str | None = None

    serial_number: str | None = None

    filesystem: str | None = None


class UsbEventResponse(BaseModel):
    id: int

    computer: str

    username: str | None = None

    event_type: str

    device_id: str | None = None

    drive_letter: str | None = None

    volume_label: str | None = None

    serial_number: str | None = None

    filesystem: str | None = None

    created_at: datetime

    model_config = {
        "from_attributes": True
    }
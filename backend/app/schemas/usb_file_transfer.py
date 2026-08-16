from datetime import datetime

from pydantic import BaseModel


class UsbFileTransferCreate(BaseModel):
    computer: str

    username: str | None = None

    device_id: str | None = None

    drive_letter: str

    file_path: str

    file_name: str

    extension: str | None = None

    file_size: int | None = None

    sha256_hash: str | None = None


class UsbFileTransferResponse(BaseModel):
    id: int

    computer: str

    username: str | None = None

    device_id: str | None = None

    drive_letter: str

    file_path: str

    file_name: str

    extension: str | None = None

    file_size: int | None = None

    sha256_hash: str | None = None

    risk_score: int

    severity: str

    created_at: datetime

    model_config = {
        "from_attributes": True
    }
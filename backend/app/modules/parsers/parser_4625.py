from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent
from app.modules.parsers.base import BaseParser


class Parser4625(BaseParser):

    @staticmethod
    def event_id() -> int:
        return 4625

    def parse(
        self,
        db: Session,
        event: RawWindowsEvent
    ) -> None:

        print(
            f"Processing Failed Login {event.event_id}"
        )
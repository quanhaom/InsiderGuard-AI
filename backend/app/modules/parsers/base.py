from abc import ABC, abstractmethod

from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent


class BaseParser(ABC):

    @staticmethod
    @abstractmethod
    def event_id() -> int:
        raise NotImplementedError

    @abstractmethod
    def parse(
        self,
        db: Session,
        event: RawWindowsEvent
    ):
        raise NotImplementedError
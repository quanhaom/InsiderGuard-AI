from abc import ABC
from abc import abstractmethod

from app.models import (
    CollectorEvent,
    RawWindowsEvent,
)


class BaseParser(ABC):

    @abstractmethod
    def parse(
        self,
        event: RawWindowsEvent
    ) -> CollectorEvent:
        """
        Convert a RawWindowsEvent into a normalized
        CollectorEvent.
        """
        raise NotImplementedError
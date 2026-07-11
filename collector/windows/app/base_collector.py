from abc import ABC, abstractmethod
from collections.abc import Iterator

from app.models import RawWindowsEvent


class BaseCollector(ABC):

    @abstractmethod
    def collect(
        self
    ) -> Iterator[RawWindowsEvent]:
        """Yield raw events from the configured source."""
        raise NotImplementedError
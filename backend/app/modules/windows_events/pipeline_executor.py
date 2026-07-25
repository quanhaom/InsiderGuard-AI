from typing import Any

from sqlalchemy.orm import Session

from app.models.raw_windows_event import (
    RawWindowsEvent,
)
from app.modules.windows_events.parser_registry import (
    ParserRegistry,
)


class WindowsPipelineExecutor:

    @classmethod
    def parse(
        cls,
        db: Session,
        event: RawWindowsEvent,
    ) -> Any | None:

        parser = ParserRegistry.get(
            provider=event.provider,
            event_id=event.event_id,
        )

        if parser is None:
            return None

        return parser.parse(
            db=db,
            event=event,
        )
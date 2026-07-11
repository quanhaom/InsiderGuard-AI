from app.models import (
    CollectorEvent,
    RawWindowsEvent,
)

from app.parsers.registry import ParserRegistry


class Normalizer:

    @staticmethod
    def normalize(
        event: RawWindowsEvent
    ) -> CollectorEvent:

        parser = ParserRegistry.get(
            event.event_id
        )

        if parser is None:

            raise ValueError(
                f"No parser registered for Event ID {event.event_id}"
            )

        return parser.parse(
            event
        )
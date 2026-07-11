from app.parsers.base import BaseParser


class ParserRegistry:

    _registry: dict[int, BaseParser] = {}

    @classmethod
    def register(
        cls,
        event_id: int,
        parser: BaseParser
    ) -> None:

        cls._registry[event_id] = parser

    @classmethod
    def get(
        cls,
        event_id: int
    ) -> BaseParser | None:

        return cls._registry.get(
            event_id
        )

    @classmethod
    def supported_events(
        cls
    ) -> list[int]:

        return sorted(
            cls._registry.keys()
        )
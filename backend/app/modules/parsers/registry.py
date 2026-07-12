from app.modules.parsers.base import BaseParser


class ParserRegistry:

    _parsers: dict[int, BaseParser] = {}

    @classmethod
    def register(
        cls,
        parser: BaseParser
    ) -> None:

        cls._parsers[
            parser.event_id()
        ] = parser

    @classmethod
    def get(
        cls,
        event_id: int
    ) -> BaseParser | None:

        return cls._parsers.get(event_id)

    @classmethod
    def supported_events(
        cls
    ) -> list[int]:

        return sorted(cls._parsers.keys())
from collections.abc import Callable
from typing import Any


ParserKey = tuple[str, int]
ParserType = Callable[..., Any] | type


class ParserRegistry:
    """
    Registry ánh xạ:

        (provider, event_id) -> parser

    Provider luôn được chuẩn hóa thành chữ thường.
    """

    _parsers: dict[ParserKey, ParserType] = {}

    @classmethod
    def _normalize_provider(
        cls,
        provider: str | None,
    ) -> str:
        return (
            provider
            or "unknown"
        ).strip().lower()

    @classmethod
    def register(
        cls,
        provider: str,
        event_id: int,
        parser: ParserType,
    ) -> None:
        key = (
            cls._normalize_provider(provider),
            event_id,
        )

        cls._parsers[key] = parser

    @classmethod
    def get(
        cls,
        provider: str | None,
        event_id: int,
    ) -> ParserType | None:
        key = (
            cls._normalize_provider(provider),
            event_id,
        )

        return cls._parsers.get(key)

    @classmethod
    def has_parser(
        cls,
        provider: str | None,
        event_id: int,
    ) -> bool:
        return (
            cls.get(
                provider=provider,
                event_id=event_id,
            )
            is not None
        )

    @classmethod
    def registered_events(
        cls,
    ) -> list[ParserKey]:
        return sorted(
            cls._parsers.keys()
        )
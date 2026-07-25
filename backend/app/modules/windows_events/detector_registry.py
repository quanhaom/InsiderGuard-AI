from collections.abc import Callable
from typing import Any


DetectorKey = tuple[str, int]
DetectorType = Callable[..., Any] | type


class DetectorRegistry:
    """
    Registry ánh xạ:

        (provider, event_id) -> detector
    """

    _detectors: dict[
        DetectorKey,
        DetectorType,
    ] = {}

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
        detector: DetectorType,
    ) -> None:
        key = (
            cls._normalize_provider(provider),
            event_id,
        )

        cls._detectors[key] = detector

    @classmethod
    def get(
        cls,
        provider: str | None,
        event_id: int,
    ) -> DetectorType | None:
        key = (
            cls._normalize_provider(provider),
            event_id,
        )

        return cls._detectors.get(key)

    @classmethod
    def has_detector(
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
    ) -> list[DetectorKey]:
        return sorted(
            cls._detectors.keys()
        )
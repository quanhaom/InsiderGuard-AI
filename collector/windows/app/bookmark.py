import json

from app.config import BOOKMARK_FILE
from app.logger import logger


class BookmarkManager:

    @staticmethod
    def load() -> int:
        if not BOOKMARK_FILE.exists():
            return 0

        try:
            with BOOKMARK_FILE.open(
                "r",
                encoding="utf-8"
            ) as file:
                data = json.load(file)

            return int(
                data.get(
                    "record_id",
                    0
                )
            )

        except (
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError
        ) as error:
            logger.warning(
                "Could not load bookmark: %s",
                error
            )

            return 0

    @staticmethod
    def save(
        record_id: int
    ) -> None:
        temporary_file = BOOKMARK_FILE.with_suffix(
            ".tmp"
        )

        with temporary_file.open(
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                {
                    "record_id": record_id
                },
                file,
                indent=4
            )

        temporary_file.replace(
            BOOKMARK_FILE
        )
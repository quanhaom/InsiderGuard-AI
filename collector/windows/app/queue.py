import json
import sqlite3
from dataclasses import asdict
from datetime import datetime

from app.config import QUEUE_DATABASE
from app.models import RawWindowsEvent


class OfflineQueue:

    def __init__(self) -> None:
        self.connection = sqlite3.connect(
            QUEUE_DATABASE
        )

        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_event_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL,
                event_json TEXT NOT NULL
            )
            """
        )

        self.connection.commit()

    def push(
        self,
        event: RawWindowsEvent
    ) -> None:
        event_json = json.dumps(
            asdict(event),
            ensure_ascii=False,
            default=str
        )

        self.connection.execute(
            """
            INSERT INTO raw_event_queue(
                record_id,
                event_json
            )
            VALUES (?, ?)
            """,
            (
                event.record_id,
                event_json
            )
        )

        self.connection.commit()

    def peek(self) -> tuple[int, RawWindowsEvent] | None:
        cursor = self.connection.execute(
            """
            SELECT
                id,
                event_json
            FROM raw_event_queue
            ORDER BY id ASC
            LIMIT 1
            """
        )

        row = cursor.fetchone()

        if row is None:
            return None

        queue_id = row[0]
        data = json.loads(row[1])

        raw_event = RawWindowsEvent(
    		record_id=int(data["record_id"]),

    		event_id=int(data["event_id"]),

    		computer=data["computer"],

    		provider=data.get(
        		"provider",
        		"Microsoft-Windows-Security-Auditing"
    ),

    timestamp=data["timestamp"],

    xml=data["xml"]
)

        return queue_id, raw_event

    def delete(
        self,
        queue_id: int
    ) -> None:
        self.connection.execute(
            """
            DELETE FROM raw_event_queue
            WHERE id = ?
            """,
            (
                queue_id,
            )
        )

        self.connection.commit()

    def size(self) -> int:
        cursor = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM raw_event_queue
            """
        )

        result = cursor.fetchone()

        return int(result[0])

    def close(self) -> None:
        self.connection.close()
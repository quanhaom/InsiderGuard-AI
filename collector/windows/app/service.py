import time

from app.bookmark import BookmarkManager
from app.collector import WindowsCollector
from app.config import POLL_INTERVAL
from app.logger import logger
from app.normalizer import Normalizer
from app.queue import OfflineQueue
from app.sender import Sender


class CollectorService:

    def __init__(self) -> None:
        self.collector = WindowsCollector()
        self.queue = OfflineQueue()
        self.is_running = False

    def collect_new_events(self) -> int:
        last_record_id = BookmarkManager.load()
        collected_count = 0

        for raw_event in self.collector.collect():

            if raw_event.record_id <= last_record_id:
                continue

            self.queue.push(
                raw_event
            )

            collected_count += 1

            logger.info(
                "Queued event ID=%s RecordID=%s",
                raw_event.event_id,
                raw_event.record_id
            )

        return collected_count

    def process_queue(self) -> int:
        sent_count = 0

        while True:
            item = self.queue.peek()

            if item is None:
                break

            queue_id, raw_event = item

            try:
                normalized_event = Normalizer.normalize(
                    raw_event
                )

            except ValueError as error:
                logger.warning(
                    "Unsupported event ID=%s: %s",
                    raw_event.event_id,
                    error
                )

                self.queue.delete(
                    queue_id
                )

                BookmarkManager.save(
                    raw_event.record_id
                )

                continue

            except Exception:
                logger.exception(
                    "Failed to normalize RecordID=%s",
                    raw_event.record_id
                )

                break

            sent = Sender.send(
                normalized_event
            )

            if not sent:
                logger.warning(
                    "Backend unavailable. "
                    "Event RecordID=%s remains queued",
                    raw_event.record_id
                )

                break

            self.queue.delete(
                queue_id
            )

            BookmarkManager.save(
                raw_event.record_id
            )

            sent_count += 1

            logger.info(
                "Processed EventID=%s RecordID=%s",
                raw_event.event_id,
                raw_event.record_id
            )

        return sent_count

    def run_once(self) -> None:
        collected_count = self.collect_new_events()
        sent_count = self.process_queue()

        logger.info(
            "Cycle completed: collected=%s sent=%s queued=%s",
            collected_count,
            sent_count,
            self.queue.size()
        )

    def run(self) -> None:
        self.is_running = True

        logger.info(
            "InsiderGuard Windows Collector started"
        )

        try:
            while self.is_running:
                self.run_once()

                time.sleep(
                    POLL_INTERVAL
                )

        except KeyboardInterrupt:
            logger.info(
                "Collector stopped by user"
            )

        except Exception:
            logger.exception(
                "Collector stopped unexpectedly"
            )

        finally:
            self.stop()

    def stop(self) -> None:
        self.is_running = False
        self.queue.close()

        logger.info(
            "InsiderGuard Windows Collector stopped"
        )
import requests

from app.config import API_URL
from app.logger import logger
from app.models import CollectorEvent


class Sender:

    @staticmethod
    def send(event: CollectorEvent) -> bool:
        body = {
            "source": event.source,
            "event_id": event.event_id,
            "computer": event.computer,
            "timestamp": event.timestamp.isoformat(),
            "payload": event.payload
        }

        try:
            response = requests.post(
                API_URL,
                json=body,
                timeout=5
            )

            if response.status_code < 300:
                logger.info(
                    "Event ID=%s sent successfully",
                    event.event_id
                )
                return True

            logger.error(
                "Backend returned status=%s body=%s",
                response.status_code,
                response.text
            )
            return False

        except requests.RequestException:
            logger.exception(
                "Failed to send Event ID=%s",
                event.event_id
            )
            return False
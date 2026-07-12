from datetime import datetime

import requests

from app.config import API_URL
from app.logger import logger


def serialize_timestamp(value):

    if isinstance(value, datetime):
        return value.isoformat()

    return value


class Sender:

    @staticmethod
    def send(event):

        body = {

            "source": event.source,

            "event_id": event.event_id,

            "record_id": event.record_id,

            "computer": event.computer,

            "provider": event.provider,

            "timestamp": serialize_timestamp(
                event.timestamp
            ),

            "xml": event.xml,

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
                    "Event ID=%s RecordID=%s sent successfully",
                    event.event_id,
                    event.record_id
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
                "Failed to send event"
            )

            return False
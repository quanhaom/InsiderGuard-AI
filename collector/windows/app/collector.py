from collections.abc import Iterator
from datetime import datetime
from xml.etree import ElementTree as ET

import win32evtlog

from app.base_collector import BaseCollector
from app.config import EVENT_LOG
from app.logger import logger
from app.models import RawWindowsEvent


EVENT_NAMESPACE = (
    "http://schemas.microsoft.com/win/2004/08/events/event"
)


class WindowsCollector(BaseCollector):

    QUERY = "*[System[(EventID=4624)]]"

    BATCH_SIZE = 50


    def collect(
        self
    ) -> Iterator[RawWindowsEvent]:

        try:
            query_handle = win32evtlog.EvtQuery(
                EVENT_LOG,
                win32evtlog.EvtQueryReverseDirection,
                self.QUERY
            )

        except Exception as error:

            logger.exception(
                "Could not open Windows Event Log: %s",
                error
            )

            return


        while True:

            try:
                events = win32evtlog.EvtNext(
                    query_handle,
                    self.BATCH_SIZE
                )

            except Exception as error:

                logger.exception(
                    "Could not read Windows events: %s",
                    error
                )

                break


            if not events:
                break


            for event_handle in events:

                try:

                    xml = win32evtlog.EvtRender(
                        event_handle,
                        win32evtlog.EvtRenderEventXml
                    )


                    yield self._build_raw_event(
                        xml
                    )


                except Exception:

                    logger.exception(
                        "Could not render Windows event"
                    )



    @staticmethod
    def _build_raw_event(
        xml: str
    ) -> RawWindowsEvent:


        root = ET.fromstring(
            xml
        )


        namespace = {
            "e": EVENT_NAMESPACE
        }


        system = root.find(
            "e:System",
            namespace
        )


        if system is None:

            raise ValueError(
                "Windows event does not contain System metadata"
            )


        event_id_element = system.find(
            "e:EventID",
            namespace
        )


        record_id_element = system.find(
            "e:EventRecordID",
            namespace
        )


        computer_element = system.find(
            "e:Computer",
            namespace
        )


        time_created_element = system.find(
            "e:TimeCreated",
            namespace
        )


        provider_element = system.find(
            "e:Provider",
            namespace
        )



        if event_id_element is None:

            raise ValueError(
                "Missing EventID"
            )


        if record_id_element is None:

            raise ValueError(
                "Missing EventRecordID"
            )



        timestamp_text = ""


        if time_created_element is not None:

            timestamp_text = (
                time_created_element.attrib.get(
                    "SystemTime",
                    ""
                )
            )



        timestamp = WindowsCollector._parse_timestamp(
            timestamp_text
        )



        computer = ""

        if computer_element is not None:

            computer = (
                computer_element.text
                or ""
            )



        provider = (
            "Unknown"
        )


        if provider_element is not None:

            provider = provider_element.attrib.get(
                "Name",
                "Unknown"
            )



        return RawWindowsEvent(

            record_id=int(
                record_id_element.text
            ),


            event_id=int(
                event_id_element.text
            ),


            computer=computer,


            provider=provider,


            timestamp=timestamp,


            xml=xml
        )



    @staticmethod
    def _parse_timestamp(
        timestamp: str
    ) -> datetime:


        if not timestamp:

            return datetime.now()



        normalized = timestamp.replace(
            "Z",
            "+00:00"
        )


        return datetime.fromisoformat(
            normalized
        )
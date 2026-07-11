from xml.etree import ElementTree as ET


def get_event_data(xml: str) -> dict[str, str]:

    root = ET.fromstring(xml)

    result: dict[str, str] = {}

    namespace = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    for data in root.findall(
        ".//e:EventData/e:Data",
        namespace
    ):

        name = data.attrib.get(
            "Name"
        )

        if name:

            result[name] = data.text or ""

    return result
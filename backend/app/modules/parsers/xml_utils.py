from xml.etree import ElementTree as ET


EVENT_NAMESPACE = (
    "http://schemas.microsoft.com/win/2004/08/events/event"
)


def get_event_data(
    xml: str
) -> dict[str, str]:
    root = ET.fromstring(
        xml
    )

    namespace = {
        "e": EVENT_NAMESPACE
    }

    result: dict[str, str] = {}

    for item in root.findall(
        ".//e:EventData/e:Data",
        namespace
    ):
        name = item.attrib.get(
            "Name"
        )

        if name:
            result[name] = item.text or ""

    return result
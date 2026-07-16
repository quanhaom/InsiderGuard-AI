from xml.etree import ElementTree as ET


EVENT_NAMESPACE = (
    "http://schemas.microsoft.com/"
    "win/2004/08/events/event"
)


def _local_name(tag: str) -> str:
    """
    Chuyển:

    {namespace}Data

    thành:

    Data
    """
    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


def get_event_data(
    xml: str,
) -> dict[str, str]:
    if not xml or not xml.strip():
        raise ValueError(
            "Windows Event XML cannot be empty"
        )

    try:
        root = ET.fromstring(xml)

    except ET.ParseError as error:
        raise ValueError(
            f"Invalid Windows Event XML: {error}"
        ) from error

    result: dict[str, str] = {}

    # Không phụ thuộc namespace.
    # Hỗ trợ cả Windows XML thật
    # và XML đơn giản dùng để test.
    for item in root.iter():
        if _local_name(item.tag) != "Data":
            continue

        name = item.attrib.get("Name")

        if not name:
            continue

        result[name] = (
            item.text or ""
        ).strip()

    return result
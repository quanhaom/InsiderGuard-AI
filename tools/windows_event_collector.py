import json
import socket
import time

from pathlib import Path
from typing import Iterable

import requests
import win32evtlog


API_URL = (
    "http://127.0.0.1:8000"
    "/api/v1/windows-events"
)

POLL_INTERVAL = 3

REQUEST_TIMEOUT = 10

MAX_EVENTS_PER_QUERY = 100


STATE_FILE = (
    Path(__file__)
    .resolve()
    .parent
    / "collector_state.json"
)


SECURITY_CHANNEL = "Security"

SYSMON_CHANNEL = (
    "Microsoft-Windows-Sysmon/Operational"
)


PROVIDER_SECURITY = (
    "Microsoft-Windows-Security-Auditing"
)

PROVIDER_SYSMON = (
    "Microsoft-Windows-Sysmon"
)


SECURITY_EVENT_IDS = {
    4624,
    4625,
    4672,
    4688,
    4720,
    4728,
}


SYSMON_EVENT_IDS = {
    1,
    3,
    11,
    13,
    22,
}


# =========================
# STATE KEYS
# =========================


def make_state_key(
    channel: str,
    event_id: int,
) -> str:

    if channel == SECURITY_CHANNEL:

        return (
            f"Security:{event_id}"
        )

    return (
        f"Sysmon:{event_id}"
    )


def default_state() -> dict[str, int]:

    result: dict[str, int] = {}

    for event_id in (
        SECURITY_EVENT_IDS
    ):

        result[
            make_state_key(
                SECURITY_CHANNEL,
                event_id,
            )
        ] = 0

    for event_id in (
        SYSMON_EVENT_IDS
    ):

        result[
            make_state_key(
                SYSMON_CHANNEL,
                event_id,
            )
        ] = 0

    return result


def load_state() -> dict[str, int]:

    state = default_state()

    if not STATE_FILE.exists():
        return state

    try:

        raw = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(
            raw,
            dict,
        ):
            return state

        for key in state:

            try:
                state[key] = int(
                    raw.get(
                        key,
                        0,
                    )
                )

            except (
                TypeError,
                ValueError,
            ):
                state[key] = 0

        return state

    except Exception as error:

        print(
            "[WARN] Could not read "
            f"collector state: {error}"
        )

        return state


def save_state(
    state: dict[str, int],
) -> None:

    temp_file = (
        STATE_FILE.with_suffix(
            ".tmp"
        )
    )

    temp_file.write_text(
        json.dumps(
            state,
            indent=2,
        ),
        encoding="utf-8",
    )

    temp_file.replace(
        STATE_FILE
    )


# =========================
# XML HELPERS
# =========================


def render_xml(
    event_handle,
) -> str:

    return win32evtlog.EvtRender(
        event_handle,
        win32evtlog.EvtRenderEventXml,
    )


def extract_record_id(
    xml: str,
) -> int | None:

    start_marker = (
        "<EventRecordID>"
    )

    end_marker = (
        "</EventRecordID>"
    )

    start = xml.find(
        start_marker
    )

    end = xml.find(
        end_marker
    )

    if (
        start == -1
        or end == -1
    ):
        return None

    start += len(
        start_marker
    )

    try:

        return int(
            xml[
                start:end
            ].strip()
        )

    except ValueError:
        return None


def extract_event_id(
    xml: str,
) -> int | None:

    start = xml.find(
        "<EventID"
    )

    if start == -1:
        return None

    open_end = xml.find(
        ">",
        start,
    )

    end = xml.find(
        "</EventID>",
        open_end,
    )

    if (
        open_end == -1
        or end == -1
    ):
        return None

    try:

        return int(
            xml[
                open_end + 1:end
            ].strip()
        )

    except ValueError:
        return None


def extract_computer(
    xml: str,
) -> str:

    start_marker = "<Computer>"
    end_marker = "</Computer>"

    start = xml.find(
        start_marker
    )

    end = xml.find(
        end_marker
    )

    if (
        start == -1
        or end == -1
    ):
        return socket.gethostname()

    start += len(
        start_marker
    )

    value = xml[
        start:end
    ].strip()

    return (
        value
        or socket.gethostname()
    )


def extract_data_value(
    xml: str,
    field_name: str,
) -> str | None:

    patterns = [
        f'<Data Name="{field_name}">',
        f"<Data Name='{field_name}'>",
    ]

    for marker in patterns:

        start = xml.find(
            marker
        )

        if start == -1:
            continue

        start += len(
            marker
        )

        end = xml.find(
            "</Data>",
            start,
        )

        if end == -1:
            continue

        value = xml[
            start:end
        ].strip()

        if value in {
            "",
            "-",
            "::",
        }:
            return None

        return value

    return None


def determine_source_ip(
    xml: str,
) -> str | None:

    candidates = [
        "IpAddress",
        "SourceIp",
        "ClientAddress",
    ]

    for field_name in candidates:

        value = (
            extract_data_value(
                xml,
                field_name,
            )
        )

        if value:
            return value

    return None


# =========================
# QUERY HELPERS
# =========================


def build_event_xpath(
    event_id: int,
    last_record_id: int,
) -> str:

    if last_record_id > 0:

        return (
            "*[System["
            f"EventID={event_id} "
            "and "
            f"EventRecordID>{last_record_id}"
            "]]"
        )

    return (
        "*[System["
        f"EventID={event_id}"
        "]]"
    )


def query_events(
    *,
    channel: str,
    event_id: int,
    last_record_id: int,
    reverse: bool = False,
    max_events: int = (
        MAX_EVENTS_PER_QUERY
    ),
) -> list[str]:

    xpath = build_event_xpath(
        event_id=event_id,
        last_record_id=last_record_id,
    )

    flags = (
        win32evtlog
        .EvtQueryChannelPath
    )

    if reverse:

        flags |= (
            win32evtlog
            .EvtQueryReverseDirection
        )

    try:

        query_handle = (
            win32evtlog.EvtQuery(
                channel,
                flags,
                xpath,
            )
        )

    except Exception as error:

        print(
            "[ERROR] Cannot query "
            f"{channel} "
            f"Event={event_id}: "
            f"{error}"
        )

        return []

    xml_events: list[str] = []

    try:

        while True:

            events = (
                win32evtlog.EvtNext(
                    query_handle,
                    max_events,
                )
            )

            if not events:
                break

            for event_handle in events:

                try:

                    xml_events.append(
                        render_xml(
                            event_handle
                        )
                    )

                except Exception as error:

                    print(
                        "[ERROR] Cannot "
                        "render event "
                        f"{event_id}: "
                        f"{error}"
                    )

                finally:

                    try:
                        win32evtlog.EvtClose(
                            event_handle
                        )

                    except Exception:
                        pass

            if reverse:
                break

    finally:

        try:
            win32evtlog.EvtClose(
                query_handle
            )

        except Exception:
            pass

    return xml_events


# =========================
# API SEND
# =========================


def send_event(
    *,
    channel: str,
    xml: str,
) -> bool:

    record_id = (
        extract_record_id(
            xml
        )
    )

    event_id = (
        extract_event_id(
            xml
        )
    )

    if (
        record_id is None
        or event_id is None
    ):

        print(
            "[SKIP] Could not "
            "extract event metadata"
        )

        return False

    computer = (
        extract_computer(
            xml
        )
    )

    source_ip = (
        determine_source_ip(
            xml
        )
    )

    provider = (
        PROVIDER_SECURITY
        if channel
        == SECURITY_CHANNEL
        else PROVIDER_SYSMON
    )

    payload = {
        "record_id":
            record_id,

        "event_id":
            event_id,

        "computer":
            computer,

        "provider":
            provider,

        "source_ip":
            source_ip,

        "xml":
            xml,
    }

    print(
        "[SEND] "
        f"{channel} "
        f"Event={event_id} "
        f"Record={record_id}"
    )

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=(
                REQUEST_TIMEOUT
            ),
        )

    except requests.RequestException as error:

        print(
            "[ERROR] API connection "
            f"Event={event_id} "
            f"Record={record_id}: "
            f"{error}"
        )

        return False

    if response.ok:

        print(
            "[OK] "
            f"{channel} "
            f"Event={event_id} "
            f"Record={record_id} "
            f"HTTP={response.status_code}"
        )

        return True

    print(
        "[ERROR] "
        f"{channel} "
        f"Event={event_id} "
        f"Record={record_id} "
        f"HTTP={response.status_code}"
    )

    print(
        response.text
    )

    return False


# =========================
# INITIAL CHECKPOINT
# =========================


def initialize_event_state(
    *,
    channel: str,
    event_id: int,
) -> int:

    events = query_events(
        channel=channel,
        event_id=event_id,
        last_record_id=0,
        reverse=True,
        max_events=1,
    )

    if not events:

        print(
            "[INIT] "
            f"{channel} "
            f"Event={event_id} "
            "Record=0"
        )

        return 0

    record_id = (
        extract_record_id(
            events[0]
        )
        or 0
    )

    print(
        "[INIT] "
        f"{channel} "
        f"Event={event_id} "
        f"Record={record_id}"
    )

    return record_id


def initialize_missing_state(
    state: dict[str, int],
) -> None:

    for event_id in (
        sorted(
            SECURITY_EVENT_IDS
        )
    ):

        key = make_state_key(
            SECURITY_CHANNEL,
            event_id,
        )

        if state.get(
            key,
            0,
        ) != 0:
            continue

        state[key] = (
            initialize_event_state(
                channel=(
                    SECURITY_CHANNEL
                ),
                event_id=event_id,
            )
        )

    for event_id in (
        sorted(
            SYSMON_EVENT_IDS
        )
    ):

        key = make_state_key(
            SYSMON_CHANNEL,
            event_id,
        )

        if state.get(
            key,
            0,
        ) != 0:
            continue

        state[key] = (
            initialize_event_state(
                channel=(
                    SYSMON_CHANNEL
                ),
                event_id=event_id,
            )
        )

    save_state(
        state
    )


# =========================
# COLLECT SINGLE EVENT TYPE
# =========================


def collect_event_type(
    *,
    channel: str,
    event_id: int,
    state: dict[str, int],
) -> None:

    key = make_state_key(
        channel,
        event_id,
    )

    last_record_id = (
        state.get(
            key,
            0,
        )
    )

    xml_events = query_events(
        channel=channel,
        event_id=event_id,
        last_record_id=(
            last_record_id
        ),
    )

    if not xml_events:
        return

    print(
        "[QUERY] "
        f"{channel} "
        f"Event={event_id} "
        f"Found={len(xml_events)} "
        f"After={last_record_id}"
    )

    # EvtQuery forward direction
    # returns oldest -> newest.
    for xml in xml_events:

        record_id = (
            extract_record_id(
                xml
            )
        )

        if record_id is None:

            print(
                "[SKIP] "
                f"{channel} "
                f"Event={event_id} "
                "missing RecordId"
            )

            continue

        # Extra protection against
        # duplicate replay.
        if (
            record_id
            <= state.get(
                key,
                0,
            )
        ):

            print(
                "[SKIP] "
                f"{channel} "
                f"Event={event_id} "
                f"Record={record_id} "
                "already processed"
            )

            continue

        sent = send_event(
            channel=channel,
            xml=xml,
        )

        if not sent:

            # Important:
            # stop processing this event
            # type here.
            #
            # We DO NOT move its checkpoint
            # beyond the failed event.
            print(
                "[RETRY] "
                f"{channel} "
                f"Event={event_id} "
                f"Record={record_id} "
                "will retry next poll"
            )

            break

        state[key] = record_id

        save_state(
            state
        )


# =========================
# COLLECT CHANNEL
# =========================


def collect_channel(
    *,
    channel: str,
    event_ids: Iterable[int],
    state: dict[str, int],
) -> None:

    for event_id in sorted(
        event_ids
    ):

        try:

            collect_event_type(
                channel=channel,
                event_id=event_id,
                state=state,
            )

        except Exception as error:

            print(
                "[ERROR] "
                f"{channel} "
                f"Event={event_id}: "
                f"{error}"
            )


# =========================
# MAIN
# =========================


def main() -> None:

    print(
        "================================="
    )

    print(
        " InsiderGuard Windows Collector v2"
    )

    print(
        "================================="
    )

    print(
        f"API: {API_URL}"
    )

    print(
        f"State: {STATE_FILE}"
    )

    print(
        "\nSecurity Events:"
    )

    print(
        sorted(
            SECURITY_EVENT_IDS
        )
    )

    print(
        "\nSysmon Events:"
    )

    print(
        sorted(
            SYSMON_EVENT_IDS
        )
    )

    state = load_state()

    initialize_missing_state(
        state
    )

    print(
        "\nInitial checkpoints:"
    )

    print(
        json.dumps(
            state,
            indent=2,
        )
    )

    print(
        "\nListening for new "
        "Windows events...\n"
    )

    try:

        while True:

            collect_channel(
                channel=(
                    SECURITY_CHANNEL
                ),
                event_ids=(
                    SECURITY_EVENT_IDS
                ),
                state=state,
            )

            collect_channel(
                channel=(
                    SYSMON_CHANNEL
                ),
                event_ids=(
                    SYSMON_EVENT_IDS
                ),
                state=state,
            )

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:

        print(
            "\nCollector stopped."
        )

        print(
            "Final checkpoints:"
        )

        print(
            json.dumps(
                state,
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
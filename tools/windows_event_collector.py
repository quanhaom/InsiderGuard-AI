import json
import os
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

STATE_FILE = Path(
    __file__
).resolve().parent / "collector_state.json"


SECURITY_CHANNEL = "Security"

SYSMON_CHANNEL = (
    "Microsoft-Windows-Sysmon/Operational"
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
}


PROVIDER_SECURITY = (
    "Microsoft-Windows-Security-Auditing"
)

PROVIDER_SYSMON = (
    "Microsoft-Windows-Sysmon"
)


def load_state() -> dict[str, int]:
    if not STATE_FILE.exists():
        return {
            SECURITY_CHANNEL: 0,
            SYSMON_CHANNEL: 0,
        }

    try:
        data = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

        return {
            SECURITY_CHANNEL: int(
                data.get(
                    SECURITY_CHANNEL,
                    0,
                )
            ),
            SYSMON_CHANNEL: int(
                data.get(
                    SYSMON_CHANNEL,
                    0,
                )
            ),
        }

    except Exception:
        return {
            SECURITY_CHANNEL: 0,
            SYSMON_CHANNEL: 0,
        }


def save_state(
    state: dict[str, int],
) -> None:
    STATE_FILE.write_text(
        json.dumps(
            state,
            indent=2,
        ),
        encoding="utf-8",
    )


def build_xpath(
    event_ids: Iterable[int],
    last_record_id: int,
) -> str:
    event_conditions = " or ".join(
        f"EventID={event_id}"
        for event_id
        in sorted(event_ids)
    )

    if last_record_id > 0:
        return (
            "*[System[("
            f"{event_conditions}"
            ") and "
            f"EventRecordID>{last_record_id}"
            "]]"
        )

    return (
        "*[System[("
        f"{event_conditions}"
        ")]]"
    )


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
    marker_start = (
        "<EventRecordID>"
    )

    marker_end = (
        "</EventRecordID>"
    )

    start = xml.find(
        marker_start
    )

    end = xml.find(
        marker_end
    )

    if (
        start == -1
        or end == -1
    ):
        return None

    start += len(
        marker_start
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
    marker_start = "<EventID"
    marker_end = "</EventID>"

    start = xml.find(
        marker_start
    )

    if start == -1:
        return None

    open_end = xml.find(
        ">",
        start,
    )

    end = xml.find(
        marker_end,
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
    marker_start = "<Computer>"
    marker_end = "</Computer>"

    start = xml.find(
        marker_start
    )

    end = xml.find(
        marker_end
    )

    if (
        start == -1
        or end == -1
    ):
        return socket.gethostname()

    start += len(
        marker_start
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

        start += len(marker)

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
        value = extract_data_value(
            xml,
            field_name,
        )

        if value:
            return value

    return None


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
            "[SKIP] Could not extract "
            "record/event ID"
        )

        return False

    computer = extract_computer(
        xml
    )

    source_ip = (
        determine_source_ip(
            xml
        )
    )

    if (
        channel
        == SECURITY_CHANNEL
    ):
        provider = (
            PROVIDER_SECURITY
        )

    else:
        provider = (
            PROVIDER_SYSMON
        )

    payload = {
        "record_id": record_id,
        "event_id": event_id,
        "computer": computer,
        "provider": provider,
        "source_ip": source_ip,
        "xml": xml,
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=10,
        )

    except requests.RequestException as error:
        print(
            f"[ERROR] API connection: "
            f"{error}"
        )

        return False

    if response.ok:
        print(
            f"[OK] "
            f"{channel} "
            f"Event={event_id} "
            f"Record={record_id} "
            f"HTTP={response.status_code}"
        )

        return True

    print(
        f"[ERROR] "
        f"{channel} "
        f"Event={event_id} "
        f"Record={record_id} "
        f"HTTP={response.status_code}"
    )

    print(
        response.text
    )

    return False


def collect_channel(
    *,
    channel: str,
    event_ids: set[int],
    last_record_id: int,
    max_events: int = 100,
) -> int:
    query = build_xpath(
        event_ids=event_ids,
        last_record_id=(
            last_record_id
        ),
    )

    try:
        query_handle = (
            win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryChannelPath,
                query,
            )
        )

    except Exception as error:
        print(
            f"[ERROR] Cannot query "
            f"{channel}: {error}"
        )

        return last_record_id

    newest_record_id = (
        last_record_id
    )

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
                    xml = render_xml(
                        event_handle
                    )

                    record_id = (
                        extract_record_id(
                            xml
                        )
                    )

                    if record_id is None:
                        continue

                    # Query normally returns
                    # oldest -> newest.
                    # Only update state after
                    # successfully sending.
                    sent = send_event(
                        channel=channel,
                        xml=xml,
                    )

                    if sent:
                        newest_record_id = max(
                            newest_record_id,
                            record_id,
                        )

                except Exception as error:
                    print(
                        "[ERROR] Event processing "
                        f"failed: {error}"
                    )

                finally:
                    try:
                        win32evtlog.EvtClose(
                            event_handle
                        )
                    except Exception:
                        pass

    finally:
        try:
            win32evtlog.EvtClose(
                query_handle
            )
        except Exception:
            pass

    return newest_record_id


def initialize_state_from_latest(
    *,
    channel: str,
    event_ids: set[int],
) -> int:
    """
    On first run, start from the newest
    existing matching record instead of
    replaying the entire Windows log.
    """

    query = build_xpath(
        event_ids=event_ids,
        last_record_id=0,
    )

    try:
        handle = win32evtlog.EvtQuery(
            channel,
            (
                win32evtlog
                .EvtQueryChannelPath
                |
                win32evtlog
                .EvtQueryReverseDirection
            ),
            query,
        )

        events = win32evtlog.EvtNext(
            handle,
            1,
        )

        if not events:
            return 0

        xml = render_xml(
            events[0]
        )

        return (
            extract_record_id(xml)
            or 0
        )

    except Exception as error:
        print(
            f"[WARN] Unable to initialize "
            f"{channel}: {error}"
        )

        return 0

    finally:
        try:
            for event_handle in (
                locals().get(
                    "events",
                    [],
                )
            ):
                win32evtlog.EvtClose(
                    event_handle
                )

            if "handle" in locals():
                win32evtlog.EvtClose(
                    handle
                )

        except Exception:
            pass


def main() -> None:
    print(
        "================================="
    )
    print(
        " InsiderGuard Windows Collector"
    )
    print(
        "================================="
    )

    print(
        f"API: {API_URL}"
    )

    state = load_state()

    # Avoid ingesting years of old events
    # when collector starts for first time.
    if state[
        SECURITY_CHANNEL
    ] == 0:
        state[
            SECURITY_CHANNEL
        ] = initialize_state_from_latest(
            channel=SECURITY_CHANNEL,
            event_ids=(
                SECURITY_EVENT_IDS
            ),
        )

    if state[
        SYSMON_CHANNEL
    ] == 0:
        state[
            SYSMON_CHANNEL
        ] = initialize_state_from_latest(
            channel=SYSMON_CHANNEL,
            event_ids=(
                SYSMON_EVENT_IDS
            ),
        )

    save_state(
        state
    )

    print(
        "Initial state:"
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

    while True:
        try:
            new_security_record = (
                collect_channel(
                    channel=(
                        SECURITY_CHANNEL
                    ),
                    event_ids=(
                        SECURITY_EVENT_IDS
                    ),
                    last_record_id=(
                        state[
                            SECURITY_CHANNEL
                        ]
                    ),
                )
            )

            if (
                new_security_record
                != state[
                    SECURITY_CHANNEL
                ]
            ):
                state[
                    SECURITY_CHANNEL
                ] = (
                    new_security_record
                )

                save_state(
                    state
                )

            new_sysmon_record = (
                collect_channel(
                    channel=(
                        SYSMON_CHANNEL
                    ),
                    event_ids=(
                        SYSMON_EVENT_IDS
                    ),
                    last_record_id=(
                        state[
                            SYSMON_CHANNEL
                        ]
                    ),
                )
            )

            if (
                new_sysmon_record
                != state[
                    SYSMON_CHANNEL
                ]
            ):
                state[
                    SYSMON_CHANNEL
                ] = (
                    new_sysmon_record
                )

                save_state(
                    state
                )

        except KeyboardInterrupt:
            print(
                "\nCollector stopped."
            )
            break

        except Exception as error:
            print(
                f"[ERROR] Collector loop: "
                f"{error}"
            )

        time.sleep(
            POLL_INTERVAL
        )


if __name__ == "__main__":
    main()
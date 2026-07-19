
import json
import time
import uuid

import requests


API_URL = (
    "http://127.0.0.1:8000"
    "/api/v1/windows-events"
)

COMPUTER_NAME = "WORKSTATION-01"

PROVIDER_NAME = (
    "Microsoft-Windows-Security-Auditing"
)


def generate_record_id() -> int:
    """
    Tạo EventRecordID giả lập.
    """

    return int(
        uuid.uuid4().int
        % 1_000_000_000
    )


def send_payload(
    payload: dict,
) -> None:
    """
    Gửi một Windows Event tới backend.
    """

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=15,
        )

        print(
            "\n"
            + "=" * 60
        )

        print(
            f"EVENT ID: "
            f"{payload.get('event_id')}"
        )

        print(
            f"RECORD ID: "
            f"{payload.get('record_id')}"
        )

        print(
            "STATUS:",
            response.status_code,
        )

        try:
            response_data = (
                response.json()
            )

            print("CONTENT:")

            print(
                json.dumps(
                    response_data,
                    indent=2,
                    ensure_ascii=False,
                )
            )

        except requests.exceptions.JSONDecodeError:
            print("CONTENT:")

            print(
                response.text
                or "<empty response>"
            )

        response.raise_for_status()

    except requests.exceptions.ConnectionError:
        print(
            "\nCould not connect to "
            "InsiderGuard backend."
        )

        print(
            "Make sure FastAPI is running at:"
        )

        print(
            "http://127.0.0.1:8000"
        )

    except requests.exceptions.Timeout:
        print(
            "\nRequest timed out."
        )

    except requests.exceptions.HTTPError as error:
        print(
            "\nBackend returned an HTTP error:"
        )

        print(error)

    except requests.exceptions.RequestException as error:
        print(
            "\nRequest failed:"
        )

        print(error)


def send_login_event(
    event_id: int,
    username: str,
    source_ip: str,
    logon_type: int = 3,
) -> None:
    """
    Gửi Event 4624 hoặc 4625.
    """

    if event_id not in {
        4624,
        4625,
    }:
        raise ValueError(
            "send_login_event only supports "
            "Event ID 4624 and 4625."
        )

    status_text = (
        "SUCCESS"
        if event_id == 4624
        else "FAILED"
    )

    failure_reason = (
        ""
        if event_id == 4624
        else "Unknown user name or bad password"
    )

    xml = f"""
<Event>
    <System>
        <Provider
            Name="{PROVIDER_NAME}"
        />

        <EventID>
            {event_id}
        </EventID>

        <EventRecordID>
            {generate_record_id()}
        </EventRecordID>

        <Computer>
            {COMPUTER_NAME}
        </Computer>
    </System>

    <EventData>
        <Data Name="TargetUserName">
            {username}
        </Data>

        <Data Name="IpAddress">
            {source_ip}
        </Data>

        <Data Name="LogonType">
            {logon_type}
        </Data>

        <Data Name="Status">
            {status_text}
        </Data>

        <Data Name="FailureReason">
            {failure_reason}
        </Data>
    </EventData>
</Event>
""".strip()

    payload = {
        "record_id": (
            generate_record_id()
        ),
        "event_id": event_id,
        "computer": COMPUTER_NAME,
        "provider": PROVIDER_NAME,
        "source_ip": source_ip,
        "xml": xml,
    }

    send_payload(
        payload
    )


def send_privilege_event(
    username: str,
    source_ip: str,
    privileges: list[str] | None = None,
) -> None:
    """
    Gửi Windows Event ID 4672:
    Special privileges assigned to new logon.
    """

    if privileges is None:
        privileges = [
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeBackupPrivilege",
        ]

    privilege_text = "\n".join(
        privileges
    )

    xml = f"""
<Event>
    <System>
        <Provider
            Name="{PROVIDER_NAME}"
        />

        <EventID>
            4672
        </EventID>

        <EventRecordID>
            {generate_record_id()}
        </EventRecordID>

        <Computer>
            {COMPUTER_NAME}
        </Computer>
    </System>

    <EventData>
        <Data Name="SubjectUserName">
            {username}
        </Data>

        <Data Name="IpAddress">
            {source_ip}
        </Data>

        <Data Name="PrivilegeList">
            {privilege_text}
        </Data>
    </EventData>
</Event>
""".strip()

    payload = {
        "record_id": (
            generate_record_id()
        ),
        "event_id": 4672,
        "computer": COMPUTER_NAME,
        "provider": PROVIDER_NAME,
        "source_ip": source_ip,
        "xml": xml,
    }

    send_payload(
        payload
    )


def run_login_scenario() -> None:
    """
    Scenario:
    - 1 successful login
    - 5 failed logins
    """

    print(
        "\nRunning login detection scenario..."
    )

    send_login_event(
        event_id=4624,
        username="alice",
        source_ip="192.168.1.20",
        logon_type=3,
    )

    time.sleep(2)

    for attempt in range(
        1,
        6,
    ):
        print(
            f"\nFailed login attempt "
            f"{attempt}/5"
        )

        send_login_event(
            event_id=4625,
            username="alice",
            source_ip="10.10.10.50",
            logon_type=3,
        )

        time.sleep(1)


def run_privilege_scenario() -> None:
    """
    Scenario:
    - Event 4672
    - dangerous privileges assigned
    """

    print(
        "\nRunning privilege escalation "
        "scenario..."
    )

    send_privilege_event(
        username="alice",
        source_ip="10.10.10.50",
        privileges=[
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeBackupPrivilege",
        ],
    )


def main() -> None:
    print(
        "InsiderGuard Windows Agent Simulator"
    )

    print(
        "Target API:",
        API_URL,
    )

    run_login_scenario()

    time.sleep(2)

    run_privilege_scenario()

    print(
        "\nAll simulated Windows events "
        "have been sent."
    )


if __name__ == "__main__":
    main()
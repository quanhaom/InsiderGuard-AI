
import json
import time
import uuid

import requests
SYSMON_PROVIDER = (
    "Microsoft-Windows-Sysmon"
)

API_URL = (
    "http://127.0.0.1:8000"
    "/api/v1/windows-events"
)

COMPUTER_NAME = "WORKSTATION-01"

PROVIDER_NAME = (
    "Microsoft-Windows-Security-Auditing"
)

def send_account_created_event(
    actor_username: str,
    target_username: str,
    target_domain: str,
    source_ip: str,
) -> None:
    record_id = generate_record_id()

    target_sid = (
        "S-1-5-21-111111111-"
        "222222222-333333333-1105"
    )

    xml = f"""
<Event>
    <System>
        <Provider
            Name="{PROVIDER_NAME}"
        />

        <EventID>
            4720
        </EventID>

        <EventRecordID>
            {record_id}
        </EventRecordID>

        <Computer>
            {COMPUTER_NAME}
        </Computer>
    </System>

    <EventData>
        <Data Name="SubjectUserName">
            {actor_username}
        </Data>

        <Data Name="TargetUserName">
            {target_username}
        </Data>

        <Data Name="TargetDomainName">
            {target_domain}
        </Data>

        <Data Name="TargetSid">
            {target_sid}
        </Data>

        <Data Name="IpAddress">
            {source_ip}
        </Data>
    </EventData>
</Event>
""".strip()

    payload = {
        "record_id": record_id,

        "event_id": 4720,

        "computer": COMPUTER_NAME,

        "provider": PROVIDER_NAME,

        "source_ip": source_ip,

        "xml": xml,
    }

    send_payload(
        payload
    )


def send_sysmon_process_event(
    username: str,
    image: str,
    command_line: str,
    parent_image: str,
) -> None:
    record_id = generate_record_id()

    xml = f"""
<Event>
    <System>
        <Provider
            Name="{SYSMON_PROVIDER}"
        />

        <EventID>
            1
        </EventID>

        <EventRecordID>
            {record_id}
        </EventRecordID>

        <Computer>
            {COMPUTER_NAME}
        </Computer>
    </System>

    <EventData>
        <Data Name="UtcTime">
            2026-07-19 08:00:00.000
        </Data>

        <Data Name="ProcessGuid">
            {{11111111-2222-3333-4444-555555555555}}
        </Data>

        <Data Name="ProcessId">
            4820
        </Data>

        <Data Name="Image">
            {image}
        </Data>

        <Data Name="CommandLine">
            {command_line}
        </Data>

        <Data Name="CurrentDirectory">
            C:\\Users\\alice\\Downloads
        </Data>

        <Data Name="User">
            {username}
        </Data>

        <Data Name="LogonGuid">
            {{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}}
        </Data>

        <Data Name="LogonId">
            0x12345
        </Data>

        <Data Name="TerminalSessionId">
            1
        </Data>

        <Data Name="IntegrityLevel">
            High
        </Data>

        <Data Name="Hashes">
            SHA256=ABCDEF1234567890,MD5=1234567890ABCDEF
        </Data>

        <Data Name="ParentProcessGuid">
            {{99999999-8888-7777-6666-555555555555}}
        </Data>

        <Data Name="ParentProcessId">
            2200
        </Data>

        <Data Name="ParentImage">
            {parent_image}
        </Data>

        <Data Name="ParentCommandLine">
            WINWORD.EXE document.docm
        </Data>
    </EventData>
</Event>
""".strip()

    payload = {
        "record_id": record_id,
        "event_id": 1,
        "computer": COMPUTER_NAME,
        "provider": SYSMON_PROVIDER,
        "source_ip": None,
        "xml": xml,
    }

    send_payload(payload)



def run_sysmon_scenario() -> None:
    print(
        "\nRunning Sysmon Event 1 scenario..."
    )

    send_sysmon_process_event(
        username=(
            "INSIDERGUARD\\alice"
        ),

        image=(
            r"C:\Windows\System32"
            r"\WindowsPowerShell\v1.0"
            r"\powershell.exe"
        ),

        command_line=(
            "powershell.exe "
            "-NoProfile "
            "-ExecutionPolicy Bypass "
            "-WindowStyle Hidden "
            "-EncodedCommand SQBFAFgA"
        ),

        parent_image=(
            r"C:\Program Files"
            r"\Microsoft Office"
            r"\root\Office16"
            r"\WINWORD.EXE"
        ),
    )

def run_account_creation_scenario() -> None:
    print(
        "\nRunning account creation "
        "scenario..."
    )

    send_account_created_event(
        actor_username="alice",

        target_username=(
            "tempadmin"
        ),

        target_domain=(
            "WORKSTATION-01"
        ),

        source_ip=(
            "10.10.10.50"
        ),
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

def send_group_membership_event(
    actor_username: str,
    member_username: str,
    group_name: str,
    group_domain: str,
    source_ip: str,
) -> None:
    record_id = generate_record_id()

    member_sid = (
        "S-1-5-21-111111111-"
        "222222222-333333333-1105"
    )

    group_sid = (
        "S-1-5-21-111111111-"
        "222222222-333333333-512"
    )

    member_distinguished_name = (
        f"CN={member_username},"
        f"CN=Users,"
        f"DC=insiderguard,"
        f"DC=local"
    )

    xml = f"""
<Event>
    <System>
        <Provider
            Name="{PROVIDER_NAME}"
        />

        <EventID>
            4728
        </EventID>

        <EventRecordID>
            {record_id}
        </EventRecordID>

        <Computer>
            {COMPUTER_NAME}
        </Computer>
    </System>

    <EventData>
        <Data Name="SubjectUserName">
            {actor_username}
        </Data>

        <Data Name="MemberName">
            {member_distinguished_name}
        </Data>

        <Data Name="MemberId">
            {member_sid}
        </Data>

        <Data Name="TargetUserName">
            {group_name}
        </Data>

        <Data Name="TargetDomainName">
            {group_domain}
        </Data>

        <Data Name="TargetSid">
            {group_sid}
        </Data>

        <Data Name="IpAddress">
            {source_ip}
        </Data>
    </EventData>
</Event>
""".strip()

    payload = {
        "record_id": record_id,

        "event_id": 4728,

        "computer": COMPUTER_NAME,

        "provider": PROVIDER_NAME,

        "source_ip": source_ip,

        "xml": xml,
    }

    send_payload(
        payload
    )

def run_group_membership_scenario() -> None:
    print(
        "\nRunning privileged group "
        "membership scenario..."
    )

    send_group_membership_event(
        actor_username="alice",

        member_username="bob",

        group_name="Domain Admins",

        group_domain=(
            "INSIDERGUARD"
        ),

        source_ip=(
            "10.10.10.50"
        ),
    )


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

    time.sleep(2)

    run_account_creation_scenario()

    time.sleep(2)

    run_group_membership_scenario()

    time.sleep(2)

    run_sysmon_scenario()

    print(
        "\nAll simulated Windows events "
        "have been sent."
    )


if __name__ == "__main__":
    main()
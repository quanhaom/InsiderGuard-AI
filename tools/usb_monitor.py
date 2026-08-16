import getpass
import hashlib
import json
import os
import socket
import subprocess
import time

from pathlib import Path

import requests


# =========================
# CONFIGURATION
# =========================

BASE_API_URL = (
    "http://localhost:8000"
    "/api/v1"
)

USB_EVENT_API_URL = (
    f"{BASE_API_URL}"
    "/usb/events"
)

FILE_TRANSFER_API_URL = (
    f"{BASE_API_URL}"
    "/usb/file-transfers"
)

POLL_INTERVAL = 3

REQUEST_TIMEOUT = 15

HASH_CHUNK_SIZE = (
    1024 * 1024
)

# Avoid hashing extremely large files
# during v1 monitoring.
MAX_HASH_FILE_SIZE = (
    1024
    * 1024
    * 1024
)

STATE_FILE = (
    Path(__file__)
    .resolve()
    .parent
    / "usb_monitor_state.json"
)


# =========================
# SYSTEM INFO
# =========================

def get_computer_name() -> str:

    return socket.gethostname()


def get_username() -> str:

    try:
        return getpass.getuser()

    except Exception:
        return "UNKNOWN"


# =========================
# USB DRIVE DISCOVERY
# =========================

def get_usb_drives() -> dict[str, dict]:

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-CimInstance "
            "Win32_LogicalDisk "
            "-Filter \"DriveType=2\" "
            "| Select-Object "
            "DeviceID,"
            "VolumeName,"
            "VolumeSerialNumber,"
            "FileSystem,"
            "Size,"
            "FreeSpace "
            "| ConvertTo-Json "
            "-Compress"
        ),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:

        raise RuntimeError(
            result.stderr.strip()
            or (
                "PowerShell removable "
                "drive query failed"
            )
        )

    output = (
        result.stdout
        .strip()
    )

    if not output:
        return {}

    try:

        raw = json.loads(
            output
        )

    except json.JSONDecodeError as error:

        raise RuntimeError(
            "Could not parse "
            "PowerShell USB output"
        ) from error

    if isinstance(
        raw,
        dict,
    ):
        raw = [
            raw
        ]

    if not isinstance(
        raw,
        list,
    ):
        return {}

    drives: dict[
        str,
        dict
    ] = {}

    for item in raw:

        if not isinstance(
            item,
            dict,
        ):
            continue

        drive_letter = (
            item.get(
                "DeviceID"
            )
        )

        if not drive_letter:
            continue

        serial_number = (
            item.get(
                "VolumeSerialNumber"
            )
        )

        device_key = (
            f"{drive_letter}|"
            f"{serial_number or 'UNKNOWN'}"
        )

        drives[
            device_key
        ] = {
            "device_id":
                device_key,

            "drive_letter":
                drive_letter,

            "volume_label":
                item.get(
                    "VolumeName"
                ),

            "serial_number":
                serial_number,

            "filesystem":
                item.get(
                    "FileSystem"
                ),

            "size":
                item.get(
                    "Size"
                ),

            "free_space":
                item.get(
                    "FreeSpace"
                ),
        }

    return drives


# =========================
# STATE
# =========================

def load_state() -> dict:

    if not STATE_FILE.exists():

        return {
            "devices": {},
            "files": {},
        }

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
            raise ValueError(
                "Invalid USB state format"
            )

        devices = (
            raw.get(
                "devices"
            )
        )

        files = (
            raw.get(
                "files"
            )
        )

        if not isinstance(
            devices,
            dict,
        ):
            devices = {}

        if not isinstance(
            files,
            dict,
        ):
            files = {}

        return {
            "devices":
                devices,

            "files":
                files,
        }

    except Exception as error:

        print(
            "[WARN] Could not load "
            f"USB state: {error}"
        )

        return {
            "devices": {},
            "files": {},
        }


def save_state(
    *,
    devices: dict,
    files: dict,
) -> None:

    state = {
        "devices":
            devices,

        "files":
            files,
    }

    temp_file = (
        STATE_FILE
        .with_suffix(
            ".tmp"
        )
    )

    temp_file.write_text(
        json.dumps(
            state,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    temp_file.replace(
        STATE_FILE
    )


# =========================
# HASHING
# =========================

def sha256_file(
    path: str,
    *,
    file_size: int | None = None,
) -> str | None:

    if (
        file_size is not None
        and file_size
        > MAX_HASH_FILE_SIZE
    ):

        print(
            "[HASH] Skip large file "
            f"{path} "
            f"Size={file_size}"
        )

        return None

    try:

        digest = (
            hashlib.sha256()
        )

        with open(
            path,
            "rb",
        ) as handle:

            while True:

                chunk = (
                    handle.read(
                        HASH_CHUNK_SIZE
                    )
                )

                if not chunk:
                    break

                digest.update(
                    chunk
                )

        return (
            digest.hexdigest()
        )

    except (
        OSError,
        PermissionError,
    ) as error:

        print(
            "[WARN] Could not hash "
            f"{path}: {error}"
        )

        return None


# =========================
# FILE SNAPSHOT
# =========================

def scan_drive_files(
    drive_letter: str,
) -> dict[str, dict]:

    root = (
        drive_letter
        + "\\"
    )

    result: dict[
        str,
        dict
    ] = {}

    if not os.path.exists(
        root
    ):
        return result

    for (
        directory,
        _directories,
        files,
    ) in os.walk(
        root
    ):

        for filename in files:

            path = (
                os.path.join(
                    directory,
                    filename,
                )
            )

            try:

                stat = os.stat(
                    path
                )

            except (
                OSError,
                PermissionError,
            ):
                continue

            normalized_key = (
                path
                .replace(
                    "/",
                    "\\",
                )
                .lower()
            )

            result[
                normalized_key
            ] = {
                "file_path":
                    path,

                "file_name":
                    filename,

                "extension":
                    os.path.splitext(
                        filename
                    )[1]
                    .lower(),

                "file_size":
                    stat.st_size,

                "mtime":
                    stat.st_mtime,
            }

    return result


# =========================
# HTTP HELPERS
# =========================

def post_json(
    *,
    url: str,
    payload: dict,
) -> requests.Response | None:

    try:

        return requests.post(
            url,
            json=payload,
            timeout=(
                REQUEST_TIMEOUT
            ),
        )

    except requests.RequestException as error:

        print(
            "[ERROR] API connection: "
            f"{error}"
        )

        return None


# =========================
# SEND DEVICE EVENT
# =========================

def send_usb_event(
    *,
    event_type: str,
    device: dict,
) -> bool:

    payload = {
        "computer":
            get_computer_name(),

        "username":
            get_username(),

        "event_type":
            event_type,

        "device_id":
            device.get(
                "device_id"
            ),

        "drive_letter":
            device.get(
                "drive_letter"
            ),

        "volume_label":
            device.get(
                "volume_label"
            ),

        "serial_number":
            device.get(
                "serial_number"
            ),

        "filesystem":
            device.get(
                "filesystem"
            ),
    }

    print(
        "[SEND] "
        f"{event_type} "
        f"Drive="
        f"{device.get('drive_letter')}"
    )

    response = post_json(
        url=(
            USB_EVENT_API_URL
        ),
        payload=payload,
    )

    if response is None:
        return False

    if not response.ok:

        print(
            "[ERROR] "
            f"{event_type} "
            f"HTTP="
            f"{response.status_code}"
        )

        print(
            response.text
        )

        return False

    print(
        "[OK] "
        f"{event_type} "
        f"Drive="
        f"{device.get('drive_letter')} "
        f"Label="
        f"{device.get('volume_label')} "
        f"Serial="
        f"{device.get('serial_number')} "
        f"HTTP="
        f"{response.status_code}"
    )

    return True


# =========================
# SEND FILE TRANSFER
# =========================

def send_file_transfer(
    *,
    device: dict,
    file_info: dict,
) -> bool:

    path = (
        file_info.get(
            "file_path"
        )
    )

    if not path:
        return False

    file_size = (
        file_info.get(
            "file_size"
        )
    )

    file_hash = (
        sha256_file(
            path,
            file_size=file_size,
        )
    )

    payload = {
        "computer":
            get_computer_name(),

        "username":
            get_username(),

        "device_id":
            device.get(
                "device_id"
            ),

        "drive_letter":
            device.get(
                "drive_letter"
            ),

        "file_path":
            path,

        "file_name":
            file_info.get(
                "file_name"
            ),

        "extension":
            file_info.get(
                "extension"
            ),

        "file_size":
            file_size,

        "sha256_hash":
            file_hash,
    }

    print(
        "[SEND] USB_FILE_CREATED "
        f"{path}"
    )

    response = post_json(
        url=(
            FILE_TRANSFER_API_URL
        ),
        payload=payload,
    )

    if response is None:
        return False

    if not response.ok:

        print(
            "[ERROR] "
            "USB_FILE_CREATED "
            f"HTTP="
            f"{response.status_code}"
        )

        print(
            response.text
        )

        return False

    try:

        body = (
            response.json()
        )

    except Exception:
        body = {}

    print(
        "[OK] USB_FILE_CREATED "
        f"{path} "
        f"Risk="
        f"{body.get('risk_score')} "
        f"Severity="
        f"{body.get('severity')} "
        f"HTTP="
        f"{response.status_code}"
    )

    return True


# =========================
# INITIALIZE FILE STATE
# =========================

def initialize_file_state(
    devices: dict,
) -> dict[
    str,
    dict
]:

    file_state = {}

    for (
        key,
        device,
    ) in devices.items():

        drive_letter = (
            device.get(
                "drive_letter"
            )
        )

        if not drive_letter:
            continue

        try:

            files = (
                scan_drive_files(
                    drive_letter
                )
            )

            file_state[
                key
            ] = files

            print(
                "[INIT] "
                f"{drive_letter} "
                f"Files="
                f"{len(files)}"
            )

        except Exception as error:

            print(
                "[WARN] Could not "
                "initialize USB files "
                f"{drive_letter}: "
                f"{error}"
            )

            file_state[
                key
            ] = {}

    return file_state


# =========================
# PROCESS CONNECTED DEVICE
# =========================

def process_connected_device(
    *,
    key: str,
    device: dict,
    file_state: dict,
) -> None:

    sent = (
        send_usb_event(
            event_type=(
                "USB_DEVICE_CONNECTED"
            ),
            device=device,
        )
    )

    if sent:

        print(
            "[DETECTED] "
            "USB connected "
            f"{device.get('drive_letter')}"
        )

    drive_letter = (
        device.get(
            "drive_letter"
        )
    )

    if not drive_letter:

        file_state[
            key
        ] = {}

        return

    try:

        # Important:
        # files already present on the
        # USB at insertion time are
        # baseline only. They are NOT
        # treated as new transfers.

        file_state[
            key
        ] = (
            scan_drive_files(
                drive_letter
            )
        )

        print(
            "[BASELINE] "
            f"{drive_letter} "
            f"Files="
            f"{len(file_state[key])}"
        )

    except Exception as error:

        print(
            "[ERROR] USB baseline "
            f"{drive_letter}: "
            f"{error}"
        )

        file_state[
            key
        ] = {}


# =========================
# PROCESS DISCONNECTED
# =========================

def process_disconnected_device(
    *,
    key: str,
    device: dict,
    file_state: dict,
) -> None:

    sent = (
        send_usb_event(
            event_type=(
                "USB_DEVICE_DISCONNECTED"
            ),
            device=device,
        )
    )

    if sent:

        print(
            "[DETECTED] "
            "USB disconnected "
            f"{device.get('drive_letter')}"
        )

    file_state.pop(
        key,
        None,
    )


# =========================
# PROCESS FILE CHANGES
# =========================

def process_device_files(
    *,
    key: str,
    device: dict,
    file_state: dict,
) -> None:

    drive_letter = (
        device.get(
            "drive_letter"
        )
    )

    if not drive_letter:
        return

    try:

        current_files = (
            scan_drive_files(
                drive_letter
            )
        )

    except Exception as error:

        print(
            "[ERROR] USB file scan "
            f"{drive_letter}: "
            f"{error}"
        )

        return

    previous_files = (
        file_state.get(
            key,
            {}
        )
    )

    previous_paths = set(
        previous_files.keys()
    )

    current_paths = set(
        current_files.keys()
    )

    new_paths = (
        current_paths
        - previous_paths
    )

    # =========================
    # NEW FILES
    # =========================

    for path_key in sorted(
        new_paths
    ):

        file_info = (
            current_files[
                path_key
            ]
        )

        print(
            "[DETECTED] "
            "New USB file "
            f"{file_info.get('file_path')}"
        )

        send_file_transfer(
            device=device,
            file_info=file_info,
        )

    # =========================
    # REPLACED / MODIFIED FILES
    # =========================
    #
    # If a file path already exists but
    # size or mtime changes, this may
    # represent overwrite/copy.
    #
    # Backend currently calls it
    # USB_FILE_CREATED for v1.

    common_paths = (
        current_paths
        & previous_paths
    )

    for path_key in (
        common_paths
    ):

        previous_info = (
            previous_files[
                path_key
            ]
        )

        current_info = (
            current_files[
                path_key
            ]
        )

        old_size = (
            previous_info.get(
                "file_size"
            )
        )

        new_size = (
            current_info.get(
                "file_size"
            )
        )

        old_mtime = (
            previous_info.get(
                "mtime"
            )
        )

        new_mtime = (
            current_info.get(
                "mtime"
            )
        )

        changed = (
            old_size != new_size
            or old_mtime
            != new_mtime
        )

        if not changed:
            continue

        print(
            "[DETECTED] "
            "Modified USB file "
            f"{current_info.get('file_path')}"
        )

        send_file_transfer(
            device=device,
            file_info=current_info,
        )

    file_state[
        key
    ] = current_files


# =========================
# MAIN
# =========================

def main() -> None:

    print(
        "================================="
    )

    print(
        " InsiderGuard USB Monitor v2"
    )

    print(
        "================================="
    )

    print(
        f"USB API: "
        f"{USB_EVENT_API_URL}"
    )

    print(
        f"File API: "
        f"{FILE_TRANSFER_API_URL}"
    )

    print(
        f"Computer: "
        f"{get_computer_name()}"
    )

    print(
        f"User: "
        f"{get_username()}"
    )

    print(
        f"Polling every "
        f"{POLL_INTERVAL}s"
    )

    print(
        f"Hash max size: "
        f"{MAX_HASH_FILE_SIZE}"
    )

    # =========================
    # INITIAL DISCOVERY
    # =========================

    try:

        current_devices = (
            get_usb_drives()
        )

    except Exception as error:

        print(
            "[ERROR] Initial USB scan: "
            f"{error}"
        )

        current_devices = {}

    state = (
        load_state()
    )

    # We intentionally baseline against
    # what is physically connected NOW.
    # This prevents stale state from a
    # previous program run generating
    # false disconnect events.

    previous_devices = (
        current_devices
    )

    file_state = (
        initialize_file_state(
            current_devices
        )
    )

    save_state(
        devices=previous_devices,
        files=file_state,
    )

    print(
        "\nInitial removable drives:"
    )

    print(
        json.dumps(
            current_devices,
            indent=2,
        )
    )

    print(
        "\nListening for USB "
        "connect/disconnect "
        "and file transfers...\n"
    )

    try:

        while True:

            # =========================
            # SCAN DEVICES
            # =========================

            try:

                current_devices = (
                    get_usb_drives()
                )

            except Exception as error:

                print(
                    "[ERROR] USB scan: "
                    f"{error}"
                )

                time.sleep(
                    POLL_INTERVAL
                )

                continue

            previous_keys = set(
                previous_devices.keys()
            )

            current_keys = set(
                current_devices.keys()
            )

            connected_keys = (
                current_keys
                - previous_keys
            )

            disconnected_keys = (
                previous_keys
                - current_keys
            )

            # =========================
            # CONNECT EVENTS
            # =========================

            for key in sorted(
                connected_keys
            ):

                device = (
                    current_devices[
                        key
                    ]
                )

                process_connected_device(
                    key=key,
                    device=device,
                    file_state=(
                        file_state
                    ),
                )

            # =========================
            # DISCONNECT EVENTS
            # =========================

            for key in sorted(
                disconnected_keys
            ):

                device = (
                    previous_devices[
                        key
                    ]
                )

                process_disconnected_device(
                    key=key,
                    device=device,
                    file_state=(
                        file_state
                    ),
                )

            # =========================
            # FILE MONITORING
            # =========================

            for (
                key,
                device,
            ) in (
                current_devices.items()
            ):

                # If just connected,
                # process_connected_device()
                # already established baseline.
                #
                # Skip file difference for
                # this poll to avoid racing
                # with device initialization.

                if (
                    key
                    in connected_keys
                ):
                    continue

                process_device_files(
                    key=key,
                    device=device,
                    file_state=(
                        file_state
                    ),
                )

            # =========================
            # ADVANCE STATE
            # =========================

            previous_devices = (
                current_devices
            )

            save_state(
                devices=(
                    previous_devices
                ),
                files=(
                    file_state
                ),
            )

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:

        print(
            "\nUSB monitor stopped."
        )

        save_state(
            devices=(
                previous_devices
            ),
            files=(
                file_state
            ),
        )

        print(
            "Final removable drives:"
        )

        print(
            json.dumps(
                previous_devices,
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
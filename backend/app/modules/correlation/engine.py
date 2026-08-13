from pathlib import PureWindowsPath
from typing import Any

from app.modules.correlation.result import (
    CorrelationResult,
)


class CorrelationEngine:

    # =========================
    # EVENT WEIGHTS
    # =========================

    EVENT_WEIGHTS = {
        1: 10,     # Process Create
        22: 10,    # DNS Query
        3: 15,     # Network Connection
        11: 20,    # File Create
        13: 25,    # Registry Value Set
    }

    # =========================
    # EVENT SEQUENCES
    # =========================

    SEQUENCE_BONUSES = {
        (
            1,
            22,
        ): 10,

        (
            1,
            3,
        ): 10,

        (
            1,
            11,
        ): 15,

        (
            11,
            13,
        ): 20,

        (
            1,
            22,
            3,
        ): 20,

        (
            1,
            3,
            11,
        ): 25,

        (
            1,
            11,
            13,
        ): 30,

        (
            1,
            22,
            3,
            11,
        ): 35,

        (
            1,
            22,
            3,
            11,
            13,
        ): 50,
    }

    # =========================
    # PROCESS REPUTATION
    # =========================

    TRUSTED_PROCESSES = {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "explorer.exe",
        "svchost.exe",
        "searchhost.exe",
        "runtimebroker.exe",
        "onedrive.exe",
    }

    HIGH_RISK_PROCESSES = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "psexec.exe",
    }

    OFFICE_PROCESSES = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
    }

    SCRIPTING_PROCESSES = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    }

    LOLBIN_PROCESSES = {
        "certutil.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "mshta.exe",
    }

    # =========================
    # DOWNLOAD FILE TYPES
    # =========================

    SCRIPT_EXTENSIONS = {
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".hta",
    }

    EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".msi",
        ".scr",
        ".com",
        ".cpl",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".rar",
        ".7z",
        ".iso",
        ".img",
    }

    # =========================
    # MITRE
    # =========================

    MITRE_MAP = {
        1: [
            "T1059",
        ],

        22: [
            "T1071.004",
        ],

        3: [
            "T1071",
        ],

        11: [
            "T1105",
        ],

        13: [
            "T1547.001",
        ],
    }

    # =========================
    # SEVERITY
    # =========================

    @staticmethod
    def _severity(
        score: int,
    ) -> str:

        if score >= 81:
            return "CRITICAL"

        if score >= 61:
            return "HIGH"

        if score >= 31:
            return "MEDIUM"

        return "LOW"

    # =========================
    # PROCESS NAME
    # =========================

    @staticmethod
    def _process_name(
        image: str | None,
    ) -> str:

        if not image:
            return ""

        normalized = (
            image
            .replace(
                "/",
                "\\",
            )
            .lower()
        )

        return (
            normalized
            .split("\\")[-1]
        )

    # =========================
    # EVENT VALUE
    # =========================

    @staticmethod
    def _event_value(
        event: dict[str, Any],
        *names: str,
    ):

        for name in names:

            value = event.get(
                name
            )

            if value not in {
                None,
                "",
            }:
                return value

        details = event.get(
            "details"
        )

        if isinstance(
            details,
            dict,
        ):

            for name in names:

                value = details.get(
                    name
                )

                if value not in {
                    None,
                    "",
                }:
                    return value

        return None

    # =========================
    # EVENT SEQUENCE
    # =========================

    @staticmethod
    def _has_sequence(
        event_ids: list[int],
        sequence: tuple[int, ...],
    ) -> bool:

        if not sequence:
            return False

        position = 0

        for event_id in event_ids:

            if (
                event_id
                == sequence[position]
            ):

                position += 1

                if (
                    position
                    == len(sequence)
                ):
                    return True

        return False

    # =========================
    # PROCESS CHAIN NAMES
    # =========================

    @classmethod
    def _chain_process_names(
        cls,
        process_chain: list[
            dict[str, Any]
        ],
    ) -> list[str]:

        names: list[str] = []

        for node in process_chain:

            name = (
                cls._process_name(
                    node.get(
                        "image"
                    )
                )
            )

            if name:
                names.append(
                    name
                )

        return names

    # =========================
    # CHAIN TRANSITION
    # =========================

    @staticmethod
    def _has_process_transition(
        process_names: list[str],
        parent_set: set[str],
        child_set: set[str],
    ) -> bool:

        if len(
            process_names
        ) < 2:
            return False

        for index in range(
            len(process_names) - 1
        ):

            parent = (
                process_names[index]
            )

            child = (
                process_names[
                    index + 1
                ]
            )

            if (
                parent in parent_set
                and child in child_set
            ):
                return True

        return False

    # =========================
    # DOWNLOAD CONTEXT
    # =========================

    @classmethod
    def _download_context(
        cls,
        events: list[
            dict[str, Any]
        ],
    ) -> tuple[
        int,
        list[str],
    ]:

        score = 0

        reasons: list[str] = []

        for event in events:

            if (
                event.get(
                    "event_id"
                )
                != 11
            ):
                continue

            target = (
                cls._event_value(
                    event,
                    "target_filename",
                    "TargetFilename",
                )
            )

            if not target:
                continue

            normalized = (
                str(target)
                .replace(
                    "/",
                    "\\",
                )
                .lower()
            )

            in_downloads = (
                "\\downloads\\"
                in normalized
            )

            extension = (
                PureWindowsPath(
                    normalized
                )
                .suffix
                .lower()
            )

            if in_downloads:

                score += 10

                reasons.append(
                    "Process tree created "
                    "a file in the user's "
                    "Downloads directory"
                )

            if (
                extension
                in cls.SCRIPT_EXTENSIONS
            ):

                score += 15

                reasons.append(
                    "Process tree created "
                    "a script file"
                )

            elif (
                extension
                in cls.EXECUTABLE_EXTENSIONS
            ):

                score += 20

                reasons.append(
                    "Process tree created "
                    "an executable file"
                )

            elif (
                extension
                in cls.ARCHIVE_EXTENSIONS
            ):

                score += 10

                reasons.append(
                    "Process tree created "
                    "an archive or disk image"
                )

            # Count only first strong
            # matching file to reduce
            # Event 11 spam inflation.
            if (
                in_downloads
                or extension
                in cls.SCRIPT_EXTENSIONS
                or extension
                in cls.EXECUTABLE_EXTENSIONS
                or extension
                in cls.ARCHIVE_EXTENSIONS
            ):
                break

        return (
            score,
            reasons,
        )

    # =========================
    # ANALYZE
    # =========================

    @classmethod
    def analyze(
        cls,
        events: list[
            dict[str, Any]
        ],
        *,
        username: str | None = None,
        computer: str | None = None,
        process_guid: str | None = None,
        process_id: int | None = None,
        process_image: str | None = None,
        parent_process_guid: (
            str | None
        ) = None,
        parent_process_id: (
            int | None
        ) = None,
        parent_image: (
            str | None
        ) = None,
        process_chain: list[
            dict[str, Any]
        ] | None = None,
    ) -> CorrelationResult:

        process_chain = (
            process_chain
            or []
        )

        # =========================
        # EMPTY
        # =========================

        if not events:

            return CorrelationResult(
                detected=False,
                score=0,
                severity="LOW",
                username=username,
                computer=computer,
                process_guid=process_guid,
                process_id=process_id,
                process_image=process_image,
                parent_process_guid=(
                    parent_process_guid
                ),
                parent_process_id=(
                    parent_process_id
                ),
                parent_image=(
                    parent_image
                ),
                process_chain=(
                    process_chain
                ),
            )

        # =========================
        # EVENT IDS
        # =========================

        event_ids = [
            int(
                event["event_id"]
            )
            for event in events
            if (
                event.get(
                    "event_id"
                )
                is not None
            )
        ]

        unique_event_ids = set(
            event_ids
        )

        # =========================
        # PROCESS CONTEXT
        # =========================

        process_name = (
            cls._process_name(
                process_image
            )
        )

        parent_process_name = (
            cls._process_name(
                parent_image
            )
        )

        chain_process_names = (
            cls._chain_process_names(
                process_chain
            )
        )

        score = 0

        reasons: list[str] = []

        mitre: set[str] = set()

        # =========================
        # BASE EVENT SCORE
        # =========================

        for event_id in (
            unique_event_ids
        ):

            points = (
                cls.EVENT_WEIGHTS.get(
                    event_id,
                    0,
                )
            )

            score += points

            if points:

                reasons.append(
                    "Observed Sysmon "
                    f"Event {event_id}"
                )

            for technique in (
                cls.MITRE_MAP.get(
                    event_id,
                    [],
                )
            ):

                mitre.add(
                    technique
                )

        # =========================
        # EVENT SEQUENCE
        # =========================

        best_sequence = None

        best_bonus = 0

        for (
            sequence,
            bonus,
        ) in (
            cls.SEQUENCE_BONUSES
            .items()
        ):

            if not cls._has_sequence(
                event_ids,
                sequence,
            ):
                continue

            if bonus > best_bonus:

                best_sequence = (
                    sequence
                )

                best_bonus = bonus

        if best_sequence:

            score += best_bonus

            sequence_text = (
                " -> ".join(
                    str(item)
                    for item
                    in best_sequence
                )
            )

            reasons.append(
                "Observed behavior "
                "sequence: "
                f"{sequence_text}"
            )

        # =========================
        # STAGE COUNT
        # =========================

        stage_count = len(
            unique_event_ids
            & {
                1,
                22,
                3,
                11,
                13,
            }
        )

        if stage_count >= 4:

            score += 20

            reasons.append(
                "Multi-stage behavior "
                "observed"
            )

        elif stage_count >= 3:

            score += 10

            reasons.append(
                "Multiple related "
                "behavior stages observed"
            )

        # =========================
        # SAME PROCESS
        # =========================

        if (
            process_guid
            and stage_count >= 2
            and len(
                process_chain
            ) <= 1
        ):

            score += 10

            reasons.append(
                "Events share the same "
                "ProcessGuid"
            )

        # =========================
        # HIGH-RISK PROCESS
        # =========================

        if (
            process_name
            in cls.HIGH_RISK_PROCESSES
        ):

            score += 20

            reasons.append(
                "Activity originated "
                "from commonly abused "
                f"process {process_name}"
            )

        # =========================
        # TREE PRESENT
        # =========================

        if len(
            process_chain
        ) >= 2:

            score += 10

            reasons.append(
                "Activity spans "
                f"{len(process_chain)} "
                "related processes"
            )

        # =========================
        # OFFICE -> SCRIPT
        # =========================

        office_to_script = (
            cls._has_process_transition(
                chain_process_names,
                cls.OFFICE_PROCESSES,
                cls.SCRIPTING_PROCESSES,
            )
        )

        if office_to_script:

            score += 30

            reasons.append(
                "Office application "
                "spawned a scripting "
                "process"
            )

            mitre.add(
                "T1059"
            )

        # Direct parent context can
        # still detect relationship if
        # parent node fell outside window.
        elif (
            parent_process_name
            in cls.OFFICE_PROCESSES
            and process_name
            in cls.SCRIPTING_PROCESSES
        ):

            score += 30

            reasons.append(
                "Office application "
                "spawned scripting "
                f"process {process_name}"
            )

            mitre.add(
                "T1059"
            )

        # =========================
        # SCRIPT -> LOLBIN
        # =========================

        script_to_lolbin = (
            cls._has_process_transition(
                chain_process_names,
                cls.SCRIPTING_PROCESSES,
                cls.LOLBIN_PROCESSES,
            )
        )

        if script_to_lolbin:

            score += 25

            reasons.append(
                "Scripting process "
                "spawned a LOLBin"
            )

            mitre.add(
                "T1218"
            )

        elif (
            parent_process_name
            in cls.SCRIPTING_PROCESSES
            and process_name
            in cls.LOLBIN_PROCESSES
        ):

            score += 25

            reasons.append(
                "Scripting process "
                "spawned LOLBin "
                f"{process_name}"
            )

            mitre.add(
                "T1218"
            )

        # =========================
        # TREE DNS
        # =========================

        if (
            len(process_chain) >= 2
            and 22
            in unique_event_ids
        ):

            score += 10

            reasons.append(
                "Related process tree "
                "performed DNS activity"
            )

        # =========================
        # TREE NETWORK
        # =========================

        if (
            len(process_chain) >= 2
            and 3
            in unique_event_ids
        ):

            score += 10

            reasons.append(
                "Related process tree "
                "performed network activity"
            )

        # =========================
        # TREE FILE
        # =========================

        if (
            len(process_chain) >= 2
            and 11
            in unique_event_ids
        ):

            score += 15

            reasons.append(
                "Related process tree "
                "created files"
            )

        # =========================
        # TREE REGISTRY
        # =========================

        if (
            len(process_chain) >= 2
            and 13
            in unique_event_ids
        ):

            score += 20

            reasons.append(
                "Related process tree "
                "modified registry state"
            )

        # =========================
        # FILE + REGISTRY
        # =========================

        if (
            11
            in unique_event_ids
            and 13
            in unique_event_ids
        ):

            score += 20

            reasons.append(
                "File creation and "
                "registry modification "
                "occurred in one chain"
            )

        # =========================
        # DOWNLOAD CONTEXT
        # =========================

        download_score, (
            download_reasons
        ) = cls._download_context(
            events
        )

        score += (
            download_score
        )

        reasons.extend(
            download_reasons
        )

        # =========================
        # HIGH CONFIDENCE CHAIN
        # =========================

        if (
            len(process_chain) >= 2
            and (
                office_to_script
                or script_to_lolbin
            )
            and (
                3 in unique_event_ids
                or 22
                in unique_event_ids
            )
            and 11
            in unique_event_ids
        ):

            score += 20

            reasons.append(
                "High-confidence "
                "execution, network and "
                "file activity chain"
            )

        # =========================
        # TRUSTED PROCESS
        # =========================

        if (
            process_name
            in cls.TRUSTED_PROCESSES
            and len(process_chain)
            <= 1
        ):

            score -= 20

            reasons.append(
                "Activity originated "
                "from commonly trusted "
                f"process {process_name}"
            )

        # =========================
        # NORMAL NETWORK
        # =========================

        normal_network_chain = {
            1,
            22,
            3,
        }

        if (
            process_name
            in cls.TRUSTED_PROCESSES
            and unique_event_ids
            .issubset(
                normal_network_chain
            )
            and len(
                process_chain
            ) <= 1
        ):

            score = min(
                score,
                25,
            )

            reasons.append(
                "Behavior matches "
                "normal application "
                "network activity"
            )

        # =========================
        # SINGLE EVENT
        # =========================

        if (
            stage_count == 1
            and len(
                process_chain
            ) <= 1
        ):

            score = min(
                score,
                25,
            )

        # =========================
        # DNS + NETWORK ONLY
        # =========================

        if (
            unique_event_ids
            .issubset(
                {
                    22,
                    3,
                }
            )
            and len(
                process_chain
            ) <= 1
        ):

            score = min(
                score,
                25,
            )

            reasons.append(
                "DNS/network activity "
                "without additional "
                "suspicious behavior"
            )

        # =========================
        # CLAMP
        # =========================

        score = max(
            0,
            min(
                score,
                100,
            ),
        )

        severity = (
            cls._severity(
                score
            )
        )

        detected = (
            score >= 31
        )

        related_process_guids = []

        for node in process_chain:

            guid = node.get(
                "process_guid"
            )

            if (
                guid
                and guid
                not in related_process_guids
            ):

                related_process_guids.append(
                    guid
                )

        return CorrelationResult(
            detected=detected,
            score=score,
            severity=severity,
            username=username,
            computer=computer,
            process_guid=process_guid,
            process_id=process_id,
            process_image=process_image,
            parent_process_guid=(
                parent_process_guid
            ),
            parent_process_id=(
                parent_process_id
            ),
            parent_image=(
                parent_image
            ),
            event_ids=event_ids,
            process_chain=(
                process_chain
            ),
            related_process_guids=(
                related_process_guids
            ),
            reasons=reasons,
            events=events,
            mitre_techniques=sorted(
                mitre
            ),
        )
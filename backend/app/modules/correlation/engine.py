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
        13: 25,    # Registry Modification
    }

    # =========================
    # SEQUENCE BONUSES
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

    # =========================
    # MITRE MAPPING
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
    # SEQUENCE DETECTION
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
    ) -> CorrelationResult:

        # =========================
        # EMPTY RESULT
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
        # CONTEXT
        # =========================

        process_name = (
            cls._process_name(
                process_image
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
                    []
                )
            ):
                mitre.add(
                    technique
                )

        # =========================
        # BEST SEQUENCE BONUS
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
                " → ".join(
                    str(item)
                    for item
                    in best_sequence
                )
            )

            reasons.append(
                "Observed process "
                "behavior sequence: "
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

        # =========================
        # MULTI-STAGE BONUS
        # =========================

        if stage_count >= 4:

            score += 20

            reasons.append(
                "Multi-stage activity "
                "observed from the same "
                "process"
            )

        elif stage_count >= 3:

            score += 10

            reasons.append(
                "Multiple related "
                "activities observed "
                "from the same process"
            )

        # =========================
        # PROCESS GUID CONFIDENCE
        # =========================

        if (
            process_guid
            and stage_count >= 2
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
                "from a commonly abused "
                "process: "
                f"{process_name}"
            )

        # =========================
        # HIGH-RISK PROCESS
        # + FILE CREATE
        # =========================

        if (
            process_name
            in cls.HIGH_RISK_PROCESSES
            and 11
            in unique_event_ids
        ):

            score += 15

            reasons.append(
                "High-risk process "
                "created a file"
            )

        # =========================
        # HIGH-RISK PROCESS
        # + REGISTRY
        # =========================

        if (
            process_name
            in cls.HIGH_RISK_PROCESSES
            and 13
            in unique_event_ids
        ):

            score += 20

            reasons.append(
                "High-risk process "
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
                "File creation followed "
                "by registry modification"
            )

        # =========================
        # TRUSTED PROCESS
        # =========================

        if (
            process_name
            in cls.TRUSTED_PROCESSES
        ):

            score -= 20

            reasons.append(
                "Activity originated "
                "from a commonly trusted "
                "process: "
                f"{process_name}"
            )

        # =========================
        # NORMAL NETWORK PATTERN
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
        ):

            score = min(
                score,
                25,
            )

            reasons.append(
                "Observed behavior "
                "matches a common "
                "application network "
                "activity pattern"
            )

        # =========================
        # SINGLE EVENT REDUCTION
        # =========================

        if stage_count == 1:

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
        ):

            score = min(
                score,
                25,
            )

            reasons.append(
                "DNS and network "
                "activity without "
                "additional suspicious "
                "process behavior"
            )

        # =========================
        # CLAMP SCORE
        # =========================

        score = max(
            0,
            min(
                score,
                100,
            ),
        )

        # =========================
        # SEVERITY
        # =========================

        severity = (
            cls._severity(
                score
            )
        )

        # =========================
        # DETECTION
        # =========================

        detected = (
            score >= 31
        )

        # =========================
        # RESULT
        # =========================

        return CorrelationResult(
            detected=detected,
            score=score,
            severity=severity,
            username=username,
            computer=computer,
            process_guid=process_guid,
            process_id=process_id,
            process_image=process_image,
            event_ids=event_ids,
            reasons=reasons,
            events=events,
            mitre_techniques=sorted(
                mitre
            ),
        )
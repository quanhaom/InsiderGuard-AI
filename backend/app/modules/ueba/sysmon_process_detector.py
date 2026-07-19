from sqlalchemy.orm import Session

from app.models.alert import Alert

from app.modules.incidents.service import (
    IncidentService,
)

from app.modules.incidents.timeline_service import (
    IncidentTimelineService,
)

from app.modules.ueba.mitre_mapping import (
    MitreMapping,
)


class SysmonProcessDetector:

    HIGH_RISK_PROCESSES = {
        "mimikatz.exe",
        "procdump.exe",
        "psexec.exe",
        "nc.exe",
        "ncat.exe",
    }

    SENSITIVE_PROCESSES = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "wmic.exe",
        "wscript.exe",
        "cscript.exe",
    }

    SUSPICIOUS_ARGUMENTS = {
        "-enc",
        "-encodedcommand",
        "frombase64string",
        "downloadstring",
        "invoke-expression",
        "iex ",
        "executionpolicy bypass",
        "windowstyle hidden",
        "-nop",
        "-noni",
        "urlcache",
        "minidump",
        "lsass.exe",
        "\\\\admin$",
    }

    SUSPICIOUS_PARENT_PAIRS = {
        (
            "winword.exe",
            "powershell.exe",
        ),
        (
            "excel.exe",
            "powershell.exe",
        ),
        (
            "outlook.exe",
            "cmd.exe",
        ),
        (
            "mshta.exe",
            "powershell.exe",
        ),
        (
            "services.exe",
            "psexec.exe",
        ),
    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed,
    ) -> dict:
        process_name = (
            parsed.process_name
            or "unknown"
        ).lower()

        parent_name = (
            parsed.parent_process_name
            or ""
        ).lower()

        command_line = (
            parsed.command_line
            or ""
        ).lower()

        risk_score = 0
        reasons: list[str] = []

        if process_name in (
            cls.HIGH_RISK_PROCESSES
        ):
            risk_score += 75

            reasons.append(
                "Known high-risk process "
                f"executed: {process_name}"
            )

        elif process_name in (
            cls.SENSITIVE_PROCESSES
        ):
            risk_score += 40

            reasons.append(
                "Security-sensitive process "
                f"executed: {process_name}"
            )

        matched_arguments = sorted(
            argument
            for argument
            in cls.SUSPICIOUS_ARGUMENTS
            if argument in command_line
        )

        if matched_arguments:
            risk_score += min(
                len(
                    matched_arguments
                ) * 10,
                40,
            )

            reasons.append(
                "Suspicious command-line "
                "arguments: "
                + ", ".join(
                    matched_arguments
                )
            )

        if (
            parent_name,
            process_name,
        ) in cls.SUSPICIOUS_PARENT_PAIRS:
            risk_score += 25

            reasons.append(
                "Suspicious parent-child "
                f"relationship: "
                f"{parent_name} -> "
                f"{process_name}"
            )

        if (
            parsed.integrity_level
            and parsed.integrity_level.lower()
            in {
                "high",
                "system",
            }
        ):
            risk_score += 10

            reasons.append(
                "Process executed with elevated "
                f"integrity level: "
                f"{parsed.integrity_level}"
            )

        risk_score = min(
            risk_score,
            100,
        )

        if risk_score < 40:
            return {
                "detected": False,
                "risk_score": risk_score,
                "severity": "LOW",
                "process_name": (
                    process_name
                ),
            }

        if risk_score >= 85:
            severity = "CRITICAL"

        elif risk_score >= 65:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        mitre = (
            MitreMapping
            .get_process_mapping(
                process_name
            )
        )

        alert = Alert(
            username=parsed.username,

            alert_type=(
                "SYSMON_SUSPICIOUS_PROCESS"
            ),

            severity=severity,

            risk_score=risk_score,

            reason="; ".join(reasons),
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        incident = (
            IncidentService
            .create_from_alert(
                db=db,
                alert=alert,
            )
        )

        if incident is not None:
            IncidentTimelineService.create_event(
                db=db,

                incident_id=incident.id,

                event_type=(
                    "SYSMON_PROCESS_DETECTED"
                ),

                actor_type="SYSTEM",

                description=(
                    "Sysmon Event 1 detected "
                    "suspicious process execution"
                ),

                event_metadata={
                    "process_guid": (
                        parsed.process_guid
                    ),

                    "process_id": (
                        parsed.process_id
                    ),

                    "process_name": (
                        process_name
                    ),

                    "image": (
                        parsed.image
                    ),

                    "command_line": (
                        parsed.command_line
                    ),

                    "parent_process_guid": (
                        parsed.parent_process_guid
                    ),

                    "parent_process_name": (
                        parsed.parent_process_name
                    ),

                    "parent_image": (
                        parsed.parent_image
                    ),

                    "hashes": (
                        parsed.hashes
                    ),

                    "integrity_level": (
                        parsed.integrity_level
                    ),

                    "risk_score": (
                        risk_score
                    ),

                    "severity": (
                        severity
                    ),

                    "mitre": mitre,
                },
            )

        return {
            "detected": True,

            "risk_score": risk_score,

            "severity": severity,

            "process_name": process_name,

            "matched_arguments": (
                matched_arguments
            ),

            "hashes": parsed.hashes,

            "mitre": mitre,

            "alert_id": alert.id,

            "incident_id": (
                incident.id
                if incident
                else None
            ),

            "incident_created": (
                incident is not None
            ),
        }
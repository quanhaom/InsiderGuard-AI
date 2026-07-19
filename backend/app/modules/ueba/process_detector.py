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


class SuspiciousProcessDetector:

    HIGH_RISK_PROCESSES = {
        "mimikatz.exe",
        "psexec.exe",
    }

    MEDIUM_RISK_PROCESSES = {
        "powershell.exe",
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
        "bypass",
        "hidden",
        "windowstyle hidden",
        "urlcache",
        "scrobj.dll",
        "javascript:",
        "vbscript:",
        "\\\\admin$",
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

        command_line = (
            parsed.command_line
            or ""
        ).lower()

        reasons: list[str] = []

        risk_score = 0

        if process_name in (
            cls.HIGH_RISK_PROCESSES
        ):
            risk_score += 80

            reasons.append(
                "Known high-risk process "
                f"executed: {process_name}"
            )

        elif process_name in (
            cls.MEDIUM_RISK_PROCESSES
        ):
            risk_score += 45

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
                )
                * 12,
                35,
            )

            reasons.append(
                "Suspicious command-line "
                "arguments: "
                + ", ".join(
                    matched_arguments
                )
            )

        parent_name = (
            parsed.parent_process_name
            or ""
        ).lower()

        suspicious_parent_pairs = {
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
                "winword.exe",
                "cmd.exe",
            ),
            (
                "services.exe",
                "psexec.exe",
            ),
        }

        if (
            parent_name,
            process_name,
        ) in suspicious_parent_pairs:
            risk_score += 25

            reasons.append(
                "Suspicious parent-child "
                "process relationship: "
                f"{parent_name} -> "
                f"{process_name}"
            )

        risk_score = min(
            risk_score,
            100,
        )

        if risk_score < 45:
            return {
                "detected": False,
                "risk_score": risk_score,
                "severity": "LOW",
                "process_name": process_name,
                "matched_arguments": (
                    matched_arguments
                ),
            }

        if risk_score >= 85:
            severity = "CRITICAL"

        elif risk_score >= 60:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        mitre = (
            MitreMapping
            .get_process_mapping(
                process_name
            )
        )

        reason = "; ".join(
            reasons
        )

        alert = Alert(
            username=parsed.username,

            alert_type=(
                "SUSPICIOUS_PROCESS"
            ),

            severity=severity,

            risk_score=risk_score,

            reason=reason,
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
                    "SUSPICIOUS_PROCESS_DETECTED"
                ),

                actor_type="SYSTEM",

                description=(
                    "Windows Event 4688 "
                    "detected suspicious "
                    "process execution"
                ),

                event_metadata={
                    "process_name": (
                        process_name
                    ),

                    "process_path": (
                        parsed.process_path
                    ),

                    "command_line": (
                        parsed.command_line
                    ),

                    "parent_process_name": (
                        parsed.parent_process_name
                    ),

                    "risk_score": (
                        risk_score
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

            "mitre": mitre,

            "alert_id": alert.id,

            "incident_id": (
                incident.id
                if incident is not None
                else None
            ),

            "incident_created": (
                incident is not None
            ),
        }
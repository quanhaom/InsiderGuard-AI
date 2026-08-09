from pathlib import PureWindowsPath

from sqlalchemy.orm import Session

from app.schemas.sysmon_file_event import (
    SysmonFileEventData,
)


class SysmonFileDetector:

    SUSPICIOUS_EXTENSIONS = {
        ".exe",
        ".dll",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".hta",
        ".scr",
    }

    SUSPICIOUS_PATHS = {
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\programdata\\",
        "\\users\\public\\",
    }

    HIGH_RISK_PATHS = {
        "\\startup\\",
    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed: SysmonFileEventData,
    ):
        del db

        target = (
            parsed.target_filename
            or ""
        )

        target_lower = (
            target.lower()
        )

        extension = (
            PureWindowsPath(
                target
            ).suffix.lower()
            if target
            else ""
        )

        risk_score = 0
        reasons: list[str] = []

        if (
            extension
            in cls.SUSPICIOUS_EXTENSIONS
        ):
            risk_score += 30

            reasons.append(
                "Executable or script file "
                f"created: {extension}"
            )

        if any(
            path in target_lower
            for path
            in cls.SUSPICIOUS_PATHS
        ):
            risk_score += 25

            reasons.append(
                "File created in a "
                "sensitive or commonly "
                "abused directory"
            )

        if any(
            path in target_lower
            for path
            in cls.HIGH_RISK_PATHS
        ):
            risk_score += 40

            reasons.append(
                "File created in a "
                "Windows Startup location"
            )

        risk_score = min(
            risk_score,
            100,
        )

        if risk_score >= 81:
            severity = "CRITICAL"

        elif risk_score >= 61:
            severity = "HIGH"

        elif risk_score >= 31:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return {
            "detected": (
                risk_score >= 31
            ),

            "alert_type": (
                "SUSPICIOUS_FILE_CREATION"
            ),

            "severity": severity,

            "risk_score": risk_score,

            "reason": (
                "; ".join(reasons)
                if reasons
                else (
                    "No suspicious file "
                    "creation indicators"
                )
            ),

            "process": parsed.image,

            "target_filename": (
                parsed.target_filename
            ),

            "user": parsed.user,
        }
from sqlalchemy.orm import Session

from app.schemas.sysmon_registry_event import (
    SysmonRegistryEventData,
)


class SysmonRegistryDetector:

    HIGH_RISK_PATHS = {
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
        "\\system\\currentcontrolset\\services\\",
        "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\",
    }

    SUSPICIOUS_VALUE_PATTERNS = {
        "powershell",
        "cmd.exe",
        "mshta",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed: SysmonRegistryEventData,
    ):
        del db

        target = (
            parsed.target_object
            or ""
        ).lower()

        details = (
            parsed.details
            or ""
        ).lower()

        risk_score = 0
        reasons: list[str] = []

        if any(
            path in target
            for path
            in cls.HIGH_RISK_PATHS
        ):
            risk_score += 50

            reasons.append(
                "Registry value modified "
                "in a persistence-sensitive location"
            )

        if any(
            pattern in details
            for pattern
            in cls.SUSPICIOUS_VALUE_PATTERNS
        ):
            risk_score += 35

            reasons.append(
                "Registry value contains "
                "a suspicious executable or script host"
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
                "SUSPICIOUS_REGISTRY_MODIFICATION"
            ),

            "severity": severity,

            "risk_score": risk_score,

            "reason": (
                "; ".join(reasons)
                if reasons
                else (
                    "No suspicious registry "
                    "modification indicators"
                )
            ),

            "target_object": (
                parsed.target_object
            ),

            "details": parsed.details,

            "process": parsed.image,

            "user": parsed.user,
        }
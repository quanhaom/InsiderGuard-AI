from sqlalchemy.orm import Session

from app.schemas.sysmon_dns_event import (
    SysmonDnsEventData,
)


class SysmonDnsDetector:

    SUSPICIOUS_PROCESSES = {
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    }

    SUSPICIOUS_TLDS = {
        ".xyz",
        ".top",
        ".click",
    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed: SysmonDnsEventData,
    ):
        del db

        query = (
            parsed.query_name
            or ""
        ).lower()

        image = (
            parsed.image
            or ""
        ).lower()

        risk_score = 0
        reasons: list[str] = []

        if any(
            image.endswith(process)
            for process
            in cls.SUSPICIOUS_PROCESSES
        ):
            risk_score += 30

            reasons.append(
                "DNS query originated from "
                "a commonly abused process"
            )

        if any(
            query.endswith(tld)
            for tld
            in cls.SUSPICIOUS_TLDS
        ):
            risk_score += 20

            reasons.append(
                "DNS query uses a "
                "higher-risk TLD"
            )

        # Long subdomains can be useful
        # as one weak DNS-tunneling signal.
        labels = query.split(".")

        if labels and len(labels[0]) >= 40:
            risk_score += 25

            reasons.append(
                "Unusually long DNS label"
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
            "detected": risk_score >= 31,

            "alert_type": (
                "SUSPICIOUS_DNS_QUERY"
            ),

            "severity": severity,

            "risk_score": risk_score,

            "reason": (
                "; ".join(reasons)
                if reasons
                else (
                    "No suspicious DNS "
                    "indicators"
                )
            ),

            "query_name": (
                parsed.query_name
            ),

            "query_results": (
                parsed.query_results
            ),

            "process": parsed.image,

            "user": parsed.user,
        }
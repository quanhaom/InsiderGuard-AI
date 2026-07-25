import ipaddress
from pathlib import PureWindowsPath

from sqlalchemy.orm import Session

from app.schemas.sysmon_network_event import (
    SysmonNetworkEventData,
)


class SysmonNetworkDetector:

    SUSPICIOUS_PROCESSES = {
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
    }

    HIGH_RISK_PORTS = {
        21,     # FTP
        22,     # SSH
        23,     # Telnet
        135,    # RPC
        139,    # NetBIOS
        445,    # SMB
        1433,   # MSSQL
        1521,   # Oracle
        3306,   # MySQL
        3389,   # RDP
        5432,   # PostgreSQL
        5900,   # VNC
        5985,   # WinRM HTTP
        5986,   # WinRM HTTPS
        6379,   # Redis
        9200,   # Elasticsearch
        27017,  # MongoDB
    }

    COMMON_WEB_PORTS = {
        80,
        443,
    }

    @staticmethod
    def _process_name(
        image: str | None,
    ) -> str:
        if not image:
            return ""

        return PureWindowsPath(
            image
        ).name.lower()

    @staticmethod
    def _is_public_ip(
        ip_value: str | None,
    ) -> bool:
        if not ip_value:
            return False

        try:
            address = ipaddress.ip_address(
                ip_value
            )
        except ValueError:
            return False

        return not any(
            (
                address.is_private,
                address.is_loopback,
                address.is_link_local,
                address.is_multicast,
                address.is_reserved,
                address.is_unspecified,
            )
        )

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed: SysmonNetworkEventData,
    ) -> dict:
        del db

        risk_score = 0
        reasons: list[str] = []

        process_name = cls._process_name(
            parsed.image
        )

        destination_port = (
            parsed.destination_port
        )

        if process_name in (
            cls.SUSPICIOUS_PROCESSES
        ):
            risk_score += 35

            reasons.append(
                "Network connection created "
                f"by suspicious process: "
                f"{process_name}"
            )

        if destination_port in (
            cls.HIGH_RISK_PORTS
        ):
            risk_score += 25

            reasons.append(
                "Connection to sensitive "
                f"destination port: "
                f"{destination_port}"
            )

        if (
            process_name
            in cls.SUSPICIOUS_PROCESSES
            and cls._is_public_ip(
                parsed.destination_ip
            )
        ):
            risk_score += 25

            reasons.append(
                "Suspicious process connected "
                "to a public IP address"
            )

        if (
            parsed.initiated is True
            and destination_port
            not in cls.COMMON_WEB_PORTS
            and cls._is_public_ip(
                parsed.destination_ip
            )
        ):
            risk_score += 15

            reasons.append(
                "Outbound connection to "
                "public IP on uncommon port"
            )

        risk_score = min(
            risk_score,
            100,
        )

        if risk_score >= 70:
            severity = "critical"
        elif risk_score >= 50:
            severity = "high"
        elif risk_score >= 25:
            severity = "medium"
        elif risk_score > 0:
            severity = "low"
        else:
            severity = "info"

        return {
            "detected": risk_score > 0,
            "alert_type": (
                "sysmon_suspicious_network_connection"
            ),
            "severity": severity,
            "risk_score": risk_score,
            "reasons": reasons,
            "details": {
                "process_guid": (
                    parsed.process_guid
                ),
                "process_id": (
                    parsed.process_id
                ),
                "image": parsed.image,
                "user": parsed.user,
                "protocol": parsed.protocol,
                "initiated": parsed.initiated,
                "source_ip": (
                    parsed.source_ip
                ),
                "source_port": (
                    parsed.source_port
                ),
                "destination_ip": (
                    parsed.destination_ip
                ),
                "destination_port": (
                    parsed.destination_port
                ),
                "destination_hostname": (
                    parsed.destination_hostname
                ),
            },
        }
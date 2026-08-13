from pathlib import PureWindowsPath

from sqlalchemy.orm import Session


class DownloadFileDetector:

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

    SUSPICIOUS_EXTENSIONS = {
        ".lnk",
        ".chm",
    }

    BROWSER_PROCESSES = {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
    }

    EMAIL_PROCESSES = {
        "outlook.exe",
        "thunderbird.exe",
    }

    HIGH_RISK_PROCESSES = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
    }

    @staticmethod
    def _safe_value(
        parsed,
        *names: str,
    ):
        for name in names:

            if isinstance(
                parsed,
                dict,
            ):
                value = parsed.get(
                    name
                )

            else:
                value = getattr(
                    parsed,
                    name,
                    None,
                )

            if value not in {
                None,
                "",
            }:
                return value

        return None

    @staticmethod
    def _process_name(
        image: str | None,
    ) -> str:

        if not image:
            return ""

        return (
            image
            .replace("/", "\\")
            .split("\\")[-1]
            .lower()
        )

    @staticmethod
    def _is_download_path(
        path: str,
    ) -> bool:

        normalized = (
            path
            .replace("/", "\\")
            .lower()
        )

        indicators = {
            "\\downloads\\",
            "\\download\\",
            "\\temporary internet files\\",
            "\\inetcache\\",
        }

        return any(
            indicator in normalized
            for indicator in indicators
        )

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

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed,
    ) -> dict:

        del db

        target_filename = (
            cls._safe_value(
                parsed,
                "target_filename",
                "TargetFilename",
            )
            or ""
        )

        image = (
            cls._safe_value(
                parsed,
                "image",
                "Image",
            )
            or ""
        )

        username = (
            cls._safe_value(
                parsed,
                "user",
                "username",
                "User",
            )
        )

        process_guid = (
            cls._safe_value(
                parsed,
                "process_guid",
                "ProcessGuid",
            )
        )

        process_id = (
            cls._safe_value(
                parsed,
                "process_id",
                "ProcessId",
            )
        )

        path = (
            target_filename
            .replace("/", "\\")
        )

        process_name = (
            cls._process_name(
                image
            )
        )

        extension = (
            PureWindowsPath(
                path
            )
            .suffix
            .lower()
        )

        score = 0

        reasons: list[str] = []

        # =========================
        # DOWNLOAD LOCATION
        # =========================

        is_download = (
            cls._is_download_path(
                path
            )
        )

        if is_download:

            score += 10

            reasons.append(
                "File created in a "
                "download-related location"
            )

        # =========================
        # SCRIPT
        # =========================

        if (
            extension
            in cls.SCRIPT_EXTENSIONS
        ):

            score += 30

            reasons.append(
                "Downloaded file has "
                "a script extension"
            )

        # =========================
        # EXECUTABLE
        # =========================

        if (
            extension
            in cls.EXECUTABLE_EXTENSIONS
        ):

            score += 35

            reasons.append(
                "Downloaded file has "
                "an executable extension"
            )

        # =========================
        # ARCHIVE
        # =========================

        if (
            extension
            in cls.ARCHIVE_EXTENSIONS
        ):

            score += 15

            reasons.append(
                "Downloaded file is "
                "an archive or disk image"
            )

        # =========================
        # OTHER SUSPICIOUS TYPE
        # =========================

        if (
            extension
            in cls.SUSPICIOUS_EXTENSIONS
        ):

            score += 25

            reasons.append(
                "Downloaded file type "
                "can be abused for execution"
            )

        # =========================
        # BROWSER SOURCE
        # =========================

        if (
            process_name
            in cls.BROWSER_PROCESSES
            and is_download
        ):

            score += 10

            reasons.append(
                "File was created "
                "by a web browser"
            )

        # =========================
        # EMAIL CLIENT SOURCE
        # =========================

        if (
            process_name
            in cls.EMAIL_PROCESSES
        ):

            score += 20

            reasons.append(
                "File originated from "
                "an email client"
            )

        # =========================
        # HIGH-RISK PROCESS
        # =========================

        if (
            process_name
            in cls.HIGH_RISK_PROCESSES
        ):

            score += 25

            reasons.append(
                "File was created by "
                "a commonly abused process"
            )

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

        return {
            "detected":
                score >= 31,

            "alert_type":
                "SUSPICIOUS_DOWNLOAD",

            "severity":
                severity,

            "risk_score":
                score,

            "reason":
                (
                    "; ".join(
                        reasons
                    )
                    if reasons
                    else (
                        "No suspicious "
                        "download indicators"
                    )
                ),

            "target_filename":
                target_filename,

            "extension":
                extension,

            "image":
                image,

            "process_guid":
                process_guid,

            "process_id":
                process_id,

            "username":
                username,

            "is_download_path":
                is_download,
        }
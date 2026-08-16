class UsbFileTransferDetector:

    SCRIPT_EXTENSIONS = {
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".hta",
    }

    EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".msi",
        ".scr",
        ".com",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".rar",
        ".7z",
        ".iso",
        ".img",
    }

    SENSITIVE_EXTENSIONS = {
        ".pem",
        ".key",
        ".pfx",
        ".p12",
        ".kdbx",
        ".sql",
        ".db",
        ".sqlite",
    }

    @staticmethod
    def severity(
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
        *,
        extension: str | None,
        file_size: int | None,
    ) -> dict:

        extension = (
            extension
            or ""
        ).lower()

        score = 15

        reasons = [
            "File written to removable storage"
        ]

        if (
            extension
            in cls.SCRIPT_EXTENSIONS
        ):
            score += 25

            reasons.append(
                "Script file copied to USB"
            )

        if (
            extension
            in cls.EXECUTABLE_EXTENSIONS
        ):
            score += 30

            reasons.append(
                "Executable copied to USB"
            )

        if (
            extension
            in cls.ARCHIVE_EXTENSIONS
        ):
            score += 15

            reasons.append(
                "Archive copied to USB"
            )

        if (
            extension
            in cls.SENSITIVE_EXTENSIONS
        ):
            score += 35

            reasons.append(
                "Potentially sensitive file type copied to USB"
            )

        if (
            file_size is not None
            and file_size >= 100 * 1024 * 1024
        ):
            score += 20

            reasons.append(
                "Large file transfer to removable storage"
            )

        score = max(
            0,
            min(
                score,
                100,
            ),
        )

        return {
            "detected":
                score >= 31,

            "risk_score":
                score,

            "severity":
                cls.severity(
                    score
                ),

            "reasons":
                reasons,
        }
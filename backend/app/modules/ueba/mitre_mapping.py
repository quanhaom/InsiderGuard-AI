class MitreMapping:

    PROCESS_TECHNIQUES = {
        "powershell.exe": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
        },

        "cmd.exe": {
            "technique_id": "T1059.003",
            "technique_name": (
                "Windows Command Shell"
            ),
            "tactic": "Execution",
        },

        "wscript.exe": {
            "technique_id": "T1059.005",
            "technique_name": (
                "Visual Basic"
            ),
            "tactic": "Execution",
        },

        "cscript.exe": {
            "technique_id": "T1059.005",
            "technique_name": (
                "Visual Basic"
            ),
            "tactic": "Execution",
        },

        "rundll32.exe": {
            "technique_id": "T1218.011",
            "technique_name": "Rundll32",
            "tactic": (
                "Defense Evasion"
            ),
        },

        "regsvr32.exe": {
            "technique_id": "T1218.010",
            "technique_name": "Regsvr32",
            "tactic": (
                "Defense Evasion"
            ),
        },

        "mshta.exe": {
            "technique_id": "T1218.005",
            "technique_name": "Mshta",
            "tactic": (
                "Defense Evasion"
            ),
        },

        "certutil.exe": {
            "technique_id": "T1105",
            "technique_name": (
                "Ingress Tool Transfer"
            ),
            "tactic": (
                "Command and Control"
            ),
        },

        "wmic.exe": {
            "technique_id": "T1047",
            "technique_name": (
                "Windows Management "
                "Instrumentation"
            ),
            "tactic": "Execution",
        },

        "psexec.exe": {
            "technique_id": "T1021.002",
            "technique_name": (
                "SMB/Windows Admin Shares"
            ),
            "tactic": (
                "Lateral Movement"
            ),
        },

        "mimikatz.exe": {
            "technique_id": "T1003",
            "technique_name": (
                "OS Credential Dumping"
            ),
            "tactic": (
                "Credential Access"
            ),
        },
    }

    @classmethod
    def get_process_mapping(
        cls,
        process_name: str,
    ) -> dict | None:
        return cls.PROCESS_TECHNIQUES.get(
            process_name.lower()
        )
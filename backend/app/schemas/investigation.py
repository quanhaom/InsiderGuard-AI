import json
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    field_validator,
)


class MitreTechniqueResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


class InvestigationReportResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: int

    incident_id: int

    summary: str

    analysis: str

    recommendations: list[str]

    mitre_techniques: list[
        MitreTechniqueResponse
    ]

    confidence: float

    model_name: str

    prompt_snapshot: str | None = None

    created_at: datetime | None = None

    @field_validator(
        "recommendations",
        mode="before",
    )
    @classmethod
    def parse_recommendations(
        cls,
        value: Any,
    ) -> list[str]:
        if value is None:
            return []

        if isinstance(value, list):
            return [
                str(item)
                for item in value
            ]

        if isinstance(value, str):
            try:
                parsed = json.loads(value)

                if isinstance(parsed, list):
                    return [
                        str(item)
                        for item in parsed
                    ]

            except json.JSONDecodeError:
                return [value]

        return [
            str(value)
        ]

    @field_validator(
        "mitre_techniques",
        mode="before",
    )
    @classmethod
    def parse_mitre_techniques(
        cls,
        value: Any,
    ) -> list[dict[str, str]]:
        if value is None:
            return []

        if isinstance(value, str):
            try:
                value = json.loads(value)

            except json.JSONDecodeError:
                return []

        if not isinstance(value, list):
            return []

        techniques: list[
            dict[str, str]
        ] = []

        for item in value:
            if isinstance(item, dict):
                technique_id = (
                    item.get(
                        "technique_id"
                    )
                    or item.get("id")
                    or "UNKNOWN"
                )

                technique_name = (
                    item.get(
                        "technique_name"
                    )
                    or item.get("name")
                    or "Unknown"
                )

                tactic = (
                    item.get("tactic")
                    or "Unknown"
                )

                techniques.append(
                    {
                        "technique_id": str(
                            technique_id
                        ),
                        "technique_name": str(
                            technique_name
                        ),
                        "tactic": str(
                            tactic
                        ),
                    }
                )

            elif isinstance(item, str):
                techniques.append(
                    {
                        "technique_id": (
                            item
                        ),
                        "technique_name": (
                            "Unknown"
                        ),
                        "tactic": (
                            "Unknown"
                        ),
                    }
                )

        return techniques
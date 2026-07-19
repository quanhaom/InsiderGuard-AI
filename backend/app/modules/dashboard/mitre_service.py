from collections import Counter

from sqlalchemy.orm import Session

from app.models.normalized_windows_event import (
    NormalizedWindowsEvent
)


class MitreDashboardService:

    @staticmethod
    def get_coverage(
        db: Session,
    ):

        events = (
            db.query(
                NormalizedWindowsEvent
            )
            .all()
        )

        counter = Counter()

        for event in events:

            details = (
                event.details or {}
            )

            mitre = details.get(
                "mitre"
            )

            if not mitre:
                continue

            technique = (
                mitre.get(
                    "technique_id"
                )
            )

            if technique:
                counter[
                    technique
                ] += 1

        return [

            {
                "technique_id": k,
                "count": v,
            }

            for k, v
            in counter.items()

        ]
from fastapi import (
    APIRouter,
    Depends,
    Query,
)

from sqlalchemy.orm import Session

from app.db.session import get_db

from app.modules.correlation.service import (
    CorrelationService,
)


router = APIRouter(
    prefix="/correlation",
    tags=["Correlation"],
)


@router.get("/processes")
def get_process_correlations(
    computer: str | None = Query(
        default=None
    ),
    window_minutes: int = Query(
        default=10,
        ge=1,
        le=1440,
    ),
    db: Session = Depends(
        get_db
    ),
):
    results = (
        CorrelationService
        .analyze_processes(
            db=db,
            computer=computer,
            window_minutes=(
                window_minutes
            ),
        )
    )

    return [
        {
            "detected":
                item.detected,

            "score":
                item.score,

            "severity":
                item.severity,

            "username":
                item.username,

            "computer":
                item.computer,

            "process_guid":
                item.process_guid,

            "process_id":
                item.process_id,

            "process_image":
                item.process_image,

            "event_ids":
                item.event_ids,

            "reasons":
                item.reasons,

            "mitre_techniques":
                item.mitre_techniques,

            "events":
                item.events,
        }
        for item in results
    ]


@router.get("/top")
def get_top_correlations(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    ),
    window_minutes: int = Query(
        default=60,
        ge=1,
        le=1440,
    ),
    db: Session = Depends(
        get_db
    ),
):
    results = (
        CorrelationService
        .analyze_processes(
            db=db,
            window_minutes=(
                window_minutes
            ),
        )
    )

    results = [
        item
        for item in results
        if item.detected
    ]

    return [
        {
            "score":
                item.score,

            "severity":
                item.severity,

            "username":
                item.username,

            "computer":
                item.computer,

            "process_guid":
                item.process_guid,

            "process_id":
                item.process_id,

            "process_image":
                item.process_image,

            "event_ids":
                item.event_ids,

            "reasons":
                item.reasons,

            "mitre_techniques":
                item.mitre_techniques,
        }
        for item
        in results[:limit]
    ]

@router.post("/process")
def process_correlations(
    computer: str | None = Query(
        default=None,
    ),
    window_minutes: int = Query(
        default=10,
        ge=1,
        le=1440,
    ),
    db: Session = Depends(
        get_db
    ),
):
    alerts = (
        CorrelationService
        .process_detections(
            db=db,
            computer=computer,
            window_minutes=(
                window_minutes
            ),
        )
    )

    return {
        "processed_alerts": len(
            alerts
        ),

        "alerts": [
            {
                "id": alert.id,
                "username":
                    alert.username,
                "alert_type":
                    alert.alert_type,
                "severity":
                    alert.severity,
                "risk_score":
                    alert.risk_score,
            }
            for alert
            in alerts
        ],
    }


@router.get(
    "/process/{process_guid}"
)
def get_process_correlation(
    process_guid: str,
    window_minutes: int = Query(
        default=60,
        ge=1,
        le=1440,
    ),
    db: Session = Depends(
        get_db
    ),
):
    results = (
        CorrelationService
        .analyze_processes(
            db=db,
            window_minutes=(
                window_minutes
            ),
        )
    )

    normalized_guid = (
        process_guid
        .strip()
        .lower()
    )

    for item in results:

        if not item.process_guid:
            continue

        if (
            item.process_guid
            .strip()
            .lower()
            == normalized_guid
        ):
            return {
                "detected":
                    item.detected,

                "score":
                    item.score,

                "severity":
                    item.severity,

                "username":
                    item.username,

                "computer":
                    item.computer,

                "process_guid":
                    item.process_guid,

                "process_id":
                    item.process_id,

                "process_image":
                    item.process_image,

                "event_ids":
                    item.event_ids,

                "reasons":
                    item.reasons,

                "mitre_techniques":
                    item.mitre_techniques,

                "events":
                    item.events,
            }

    return {
        "detail":
            "Process correlation not found"
    }

    
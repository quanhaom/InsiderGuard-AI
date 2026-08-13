from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)

from sqlalchemy.orm import Session

from app.db.session import (
    get_db,
)

from app.modules.correlation.service import (
    CorrelationService,
)


router = APIRouter(
    prefix="/correlation",
    tags=[
        "Correlation",
    ],
)


# =========================
# SERIALIZER
# =========================

def serialize_result(
    item,
    *,
    include_events: bool = True,
):

    result = {
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

        "parent_process_guid":
            item.parent_process_guid,

        "parent_process_id":
            item.parent_process_id,

        "parent_image":
            item.parent_image,

        "process_chain":
            item.process_chain,

        "related_process_guids":
            item.related_process_guids,

        "event_ids":
            item.event_ids,

        "reasons":
            item.reasons,

        "mitre_techniques":
            item.mitre_techniques,
    }

    if include_events:

        result[
            "events"
        ] = item.events

    return result


# =========================
# SAME-PROCESS VIEW
# =========================

@router.get(
    "/processes"
)
def get_process_correlations(
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
        serialize_result(
            item
        )
        for item
        in results
    ]


# =========================
# TREE RANKING
# =========================

@router.get(
    "/top"
)
def get_top_correlations(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    ),

    computer: str | None = Query(
        default=None,
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
        .analyze_process_trees(
            db=db,
            computer=computer,
            window_minutes=(
                window_minutes
            ),
        )
    )

    detected = [
        item
        for item
        in results
        if item.detected
    ]

    return [
        serialize_result(
            item,
            include_events=False,
        )
        for item
        in detected[:limit]
    ]


# =========================
# TREE LIST
# =========================

@router.get(
    "/trees"
)
def get_tree_correlations(
    computer: str | None = Query(
        default=None,
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
        .analyze_process_trees(
            db=db,
            computer=computer,
            window_minutes=(
                window_minutes
            ),
        )
    )

    return [
        serialize_result(
            item
        )
        for item
        in results
    ]


# =========================
# RAW PROCESS TREE
# =========================

@router.get(
    "/tree"
)
def get_process_tree(
    computer: str | None = Query(
        default=None,
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

    return (
        CorrelationService
        .get_process_tree(
            db=db,
            computer=computer,
            window_minutes=(
                window_minutes
            ),
        )
    )


# =========================
# TREE DETAIL
# =========================

@router.get(
    "/tree/{process_guid}"
)
def get_tree_correlation(
    process_guid: str,

    window_minutes: int = Query(
        default=60,
        ge=1,
        le=1440,
    ),

    computer: str | None = Query(
        default=None,
    ),

    db: Session = Depends(
        get_db
    ),
):

    result = (
        CorrelationService
        .analyze_process_tree(
            db=db,

            process_guid=(
                process_guid
            ),

            computer=computer,

            window_minutes=(
                window_minutes
            ),
        )
    )

    if result is None:

        raise HTTPException(
            status_code=404,

            detail=(
                "Process tree "
                "correlation not found"
            ),
        )

    return (
        serialize_result(
            result
        )
    )


# =========================
# CREATE INCIDENT
# =========================

@router.post(
    "/tree/{process_guid}/incident"
)
def create_tree_incident(
    process_guid: str,

    computer: str | None = Query(
        default=None,
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

    created = (
        CorrelationService
        .create_incident_from_tree(
            db=db,

            process_guid=(
                process_guid
            ),

            computer=computer,

            window_minutes=(
                window_minutes
            ),
        )
    )

    if created is None:

        raise HTTPException(
            status_code=400,

            detail=(
                "Correlation did not "
                "produce an alert"
            ),
        )

    result = (
        created[
            "result"
        ]
    )

    alert = (
        created[
            "alert"
        ]
    )

    incident = (
        created[
            "incident"
        ]
    )

    correlation_evidence = (
        created.get(
            "correlation_evidence"
        )
    )

    return {
        "correlation": {
            "score":
                result.score,

            "severity":
                result.severity,

            "process_guid":
                result.process_guid,

            "process_chain":
                result.process_chain,

            "event_ids":
                result.event_ids,

            "mitre_techniques":
                result.mitre_techniques,

            "reasons":
                result.reasons,
        },

        "alert": {
            "id":
                alert.id,

            "alert_type":
                alert.alert_type,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,
        },

        "incident": (
            None
            if incident is None
            else {
                "id":
                    incident.id,

                "title":
                    incident.title,

                "severity":
                    incident.severity,

                "status":
                    incident.status,
            }
        ),

        "evidence": (
            None
            if correlation_evidence
            is None
            else {
                "id":
                    correlation_evidence.id,

                "incident_id":
                    correlation_evidence
                    .incident_id,

                "evidence_type":
                    correlation_evidence
                    .evidence_type,

                "sha256_hash":
                    correlation_evidence
                    .sha256_hash,

                "created_at":
                    correlation_evidence
                    .created_at,
            }
        ),
    }


# =========================
# MANUAL SAME-PROCESS BATCH
# =========================

@router.post(
    "/process"
)
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
        "processed_alerts":
            len(alerts),

        "alerts": [
            {
                "id":
                    alert.id,

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


# =========================
# MANUAL TREE PERSIST
# =========================

@router.post(
    "/tree/{process_guid}/process"
)
def process_tree_correlation(
    process_guid: str,

    computer: str | None = Query(
        default=None,
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

    alert = (
        CorrelationService
        .process_tree_detection(
            db=db,

            process_guid=(
                process_guid
            ),

            computer=computer,

            window_minutes=(
                window_minutes
            ),
        )
    )

    if alert is None:

        return {
            "detected":
                False,

            "alert":
                None,
        }

    return {
        "detected":
            True,

        "alert": {
            "id":
                alert.id,

            "alert_type":
                alert.alert_type,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,

            "username":
                alert.username,
        },
    }
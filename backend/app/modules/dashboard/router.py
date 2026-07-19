from fastapi import (
    APIRouter,
    Depends,
    Query,
)

from sqlalchemy.orm import Session

from app.db.dependencies import get_db

from app.modules.dashboard.service import (
    DashboardService,
)


router = APIRouter(
    prefix="/dashboard",
    tags=["SOC Dashboard"],
)


@router.get("/overview")
def get_dashboard_overview(
    db: Session = Depends(get_db),
):
    return DashboardService.get_overview(
        db=db,
    )


@router.get("/incident-statistics")
def get_incident_statistics(
    db: Session = Depends(get_db),
):
    return (
        DashboardService
        .get_incident_statistics(
            db=db,
        )
    )


@router.get("/top-risk-users")
def get_top_risk_users(
    limit: int = Query(
        default=5,
        ge=1,
        le=100,
    ),
    db: Session = Depends(get_db),
):
    return (
        DashboardService
        .get_top_risk_users(
            db=db,
            limit=limit,
        )
    )
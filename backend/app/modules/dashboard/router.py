from fastapi import (
    APIRouter,
    Depends,
)

from sqlalchemy.orm import Session

from app.db.dependencies import get_db

from app.modules.dashboard.service import (
    DashboardService,
)
from app.modules.dashboard.mitre_service import (
    MitreDashboardService,
)



router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)

@router.get("/mitre")
def mitre_dashboard(
    db: Session = Depends(get_db)
):
    return (
        MitreDashboardService
        .get_coverage(
            db=db
        )
    )

@router.get(
    "/overview"
)
def dashboard_overview(
    db: Session = Depends(get_db)
):

    return (
        DashboardService
        .get_overview(db)
    )



@router.get(
    "/incidents"
)
def dashboard_incidents(
    db: Session = Depends(get_db)
):

    return (
        DashboardService
        .get_incident_statistics(
            db
        )
    )



@router.get(
    "/top-risk-users"
)
def dashboard_top_users(
    db: Session = Depends(get_db)
):

    return (
        DashboardService
        .get_top_risk_users(
            db
        )
    )
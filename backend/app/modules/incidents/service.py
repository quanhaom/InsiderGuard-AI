from datetime import datetime

from sqlalchemy.orm import Session

from app.models.alert import (
    Alert,
)

from app.models.incident import (
    Incident,
)

from app.modules.incidents.timeline_service import (
    IncidentTimelineService,
)

from app.modules.evidence.service import (
    EvidenceService,
)


class IncidentService:

    # =========================
    # CREATE FROM ALERT
    # =========================

    @staticmethod
    def create_from_alert(
        db: Session,
        alert: Alert,
    ):

        # Only HIGH / CRITICAL
        # alerts become incidents.

        if alert.severity not in {
            "HIGH",
            "CRITICAL",
        }:
            return None

        # =========================
        # DEDUP
        # =========================

        existing = (
            db.query(
                Incident
            )
            .filter(
                Incident.alert_id
                == alert.id
            )
            .first()
        )

        if existing:
            return existing

        # =========================
        # CREATE INCIDENT
        # =========================

        incident = Incident(
            alert_id=alert.id,

            username=(
                alert.username
            ),

            title=(
                "Suspicious user "
                "behavior detected"
            ),

            severity=(
                alert.severity
            ),

            status="OPEN",

            description=(
                alert.reason
            ),
        )

        db.add(
            incident
        )

        db.commit()

        db.refresh(
            incident
        )

        # =========================
        # AUDIT EVENT
        # =========================

        IncidentTimelineService.create_event(
            db=db,

            incident_id=(
                incident.id
            ),

            event_type=(
                "INCIDENT_CREATED"
            ),

            actor_type="SYSTEM",

            description=(
                "Incident created "
                "from security alert"
            ),

            event_metadata={
                "alert_id":
                    alert.id,

                "severity":
                    alert.severity,

                "risk_score":
                    alert.risk_score,
            },
        )

        # =========================
        # INCIDENT SNAPSHOT
        # =========================

        snapshot = {
            "snapshot_type":
                "INCIDENT_SNAPSHOT",

            "incident_id":
                incident.id,

            "username":
                incident.username,

            "alert_id":
                alert.id,

            "alert_type":
                alert.alert_type,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,

            "reason":
                alert.reason,

            "status":
                incident.status,

            "created_at":
                datetime.utcnow()
                .isoformat(),
        }

        EvidenceService.create_snapshot(
            db=db,

            incident_id=(
                incident.id
            ),

            username=(
                incident.username
                or "UNKNOWN"
            ),

            snapshot=snapshot,

            evidence_type=(
                "INCIDENT_SNAPSHOT"
            ),
        )

        return incident

    # =========================
    # ALL INCIDENTS
    # =========================

    @staticmethod
    def get_all_incidents(
        db: Session,
    ):

        return (
            db.query(
                Incident
            )
            .order_by(
                Incident
                .created_at
                .desc()
            )
            .all()
        )

    # =========================
    # USER INCIDENTS
    # =========================

    @staticmethod
    def get_user_incidents(
        db: Session,
        username: str,
    ):

        return (
            db.query(
                Incident
            )
            .filter(
                Incident.username
                == username
            )
            .order_by(
                Incident
                .created_at
                .desc()
            )
            .all()
        )

    # =========================
    # SINGLE INCIDENT
    # =========================

    @staticmethod
    def get_incident(
        db: Session,
        incident_id: int,
    ):

        return (
            db.query(
                Incident
            )
            .filter(
                Incident.id
                == incident_id
            )
            .first()
        )

    # =========================
    # UPDATE STATUS
    # =========================

    @staticmethod
    def update_status(
        db: Session,
        incident: Incident,
        new_status: str,
    ):

        allowed_statuses = {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED",
            "CLOSED",
        }

        if (
            new_status
            not in allowed_statuses
        ):
            raise ValueError(
                "Invalid incident status"
            )

        old_status = (
            incident.status
        )

        if (
            old_status
            == new_status
        ):
            return incident

        incident.status = (
            new_status
        )

        if (
            new_status
            == "CLOSED"
        ):
            incident.closed_at = (
                datetime.utcnow()
            )

        else:
            incident.closed_at = (
                None
            )

        db.commit()

        db.refresh(
            incident
        )

        # =========================
        # AUDIT EVENT
        # =========================

        IncidentTimelineService.create_event(
            db=db,

            incident_id=(
                incident.id
            ),

            event_type=(
                "STATUS_CHANGED"
            ),

            actor_type="ANALYST",

            actor_name=(
                "security_admin"
            ),

            description=(
                f"Status changed "
                f"{old_status} "
                f"-> {new_status}"
            ),

            old_status=(
                old_status
            ),

            new_status=(
                new_status
            ),

            event_metadata={
                "previous_status":
                    old_status,

                "new_status":
                    new_status,
            },
        )

        return incident
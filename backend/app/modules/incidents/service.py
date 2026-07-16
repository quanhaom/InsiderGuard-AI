from datetime import datetime

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident

from app.modules.incidents.timeline_service import (
    IncidentTimelineService
)

from app.modules.evidence.service import (
    EvidenceService,
)

from app.modules.blockchain.service import (
    BlockchainService,
)



class IncidentService:


    @staticmethod
    def create_from_alert(
        db: Session,
        alert: Alert
    ):


        # Chỉ tạo incident cho HIGH/CRITICAL

        if alert.severity not in [
            "HIGH",
            "CRITICAL",
        ]:
            return None



        # tránh duplicate incident

        existing = (
            db.query(Incident)
            .filter(
                Incident.alert_id
                == alert.id
            )
            .first()
        )


        if existing:

            return existing




        incident = Incident(

            alert_id=alert.id,

            username=alert.username,

            title=(
                "Suspicious user "
                "behavior detected"
            ),

            severity=alert.severity,

            status="OPEN",

            description=alert.reason

        )



        db.add(
            incident
        )

        db.commit()

        db.refresh(
            incident
        )




        # ==============================
        # SOC AUDIT EVENT
        # INCIDENT CREATED
        # ==============================

        IncidentTimelineService.create_event(

            db=db,

            incident_id=incident.id,

            event_type="INCIDENT_CREATED",

            actor_type="SYSTEM",

            description=
            "Incident created from security alert",

            event_metadata={

                "alert_id": alert.id,

                "severity": alert.severity,

                "risk_score": alert.risk_score

            }

        )





        snapshot = {

            "incident_id":
                incident.id,


            "username":
                incident.username,


            "alert_id":
                alert.id,


            "severity":
                alert.severity,


            "risk_score":
                alert.risk_score,


            "reason":
                alert.reason,


            "created_at":
                datetime.utcnow()
                .isoformat()

        }





        evidence = (

            EvidenceService
            .create_snapshot(

                db=db,

                incident_id=incident.id,

                username=incident.username,

                snapshot=snapshot

            )

        )





        # ==============================
        # BLOCKCHAIN SEAL
        # ==============================

        if evidence:


            BlockchainService.create_block(

                db=db,

                evidence_id=evidence.id,

                evidence_hash=evidence.sha256_hash

            )




        return incident





    @staticmethod
    def get_all_incidents(
        db: Session
    ):

        return (

            db.query(Incident)

            .order_by(
                Incident.created_at.desc()
            )

            .all()

        )





    @staticmethod
    def get_user_incidents(
        db: Session,
        username: str
    ):


        return (

            db.query(Incident)

            .filter(
                Incident.username
                ==
                username
            )

            .order_by(
                Incident.created_at.desc()
            )

            .all()

        )





    @staticmethod
    def get_incident(
        db: Session,
        incident_id: int
    ):


        return (

            db.query(Incident)

            .filter(
                Incident.id
                ==
                incident_id
            )

            .first()

        )





    @staticmethod
    def update_status(
        db: Session,
        incident: Incident,
        new_status: str
    ):


        allowed_statuses = [

            "OPEN",

            "INVESTIGATING",

            "RESOLVED",

            "CLOSED",

        ]



        if new_status not in allowed_statuses:

            raise ValueError(
                "Invalid incident status"
            )



        old_status = incident.status




        # không tạo audit nếu không đổi

        if old_status == new_status:

            return incident





        incident.status = new_status




        if new_status == "CLOSED":

            incident.closed_at = (

                datetime.utcnow()

            )

        else:

            incident.closed_at = None






        db.commit()


        db.refresh(
            incident
        )





        # ==============================
        # SOC AUDIT EVENT
        # STATUS CHANGED
        # ==============================

        IncidentTimelineService.create_event(

            db=db,

            incident_id=incident.id,

            event_type="STATUS_CHANGED",

            actor_type="ANALYST",

            actor_name="security_admin",

            description=(

                f"Status changed "
                f"{old_status} -> {new_status}"

            ),


            old_status=old_status,


            new_status=new_status,


            event_metadata={

                "previous_status":
                    old_status,


                "new_status":
                    new_status

            }

        )




        return incident
from datetime import datetime, timedelta

from app.db.session import SessionLocal

from app.models.failed_login_event import FailedLoginEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.evidence import Evidence
from app.models.risk_assessment import RiskAssessment


db = SessionLocal()


def seed():


    # ======================
    # Failed Login Events
    # ======================

    failed_events = [

        FailedLoginEvent(
            username="administrator",
            source_ip="192.168.1.50",
            failure_reason="Bad password",
            status="FAILED",
            sub_status="0xC000006A",
            failed_time=datetime.utcnow()
        ),


        FailedLoginEvent(
            username="administrator",
            source_ip="192.168.1.50",
            failure_reason="Bad password",
            status="FAILED",
            sub_status="0xC000006A",
            failed_time=datetime.utcnow()
            - timedelta(minutes=1)
        ),


        FailedLoginEvent(
            username="admin",
            source_ip="10.0.0.25",
            failure_reason="Unknown user",
            status="FAILED",
            sub_status="0xC0000064",
            failed_time=datetime.utcnow()
        )

    ]


    db.add_all(
        failed_events
    )


    # ======================
    # Risk Assessment
    # ======================

    risk = RiskAssessment(

        username="administrator",

        risk_score=92,

        severity="HIGH",

        reason=
        "Multiple failed login attempts followed by successful login"

    )


    db.add(risk)



    # ======================
    # Alert
    # ======================

    alert = Alert(

        username="administrator",

        alert_type="BRUTE_FORCE",

        severity="HIGH",

        risk_score=92,

        reason=
        "Multiple failed authentication attempts detected"

    )


    db.add(alert)


    db.flush()



    # ======================
    # Incident
    # ======================

    incident = Incident(

        alert_id=alert.id,

        username="administrator",

        title=
        "Possible Account Compromise",

        severity="HIGH",

        status="OPEN",

        description=
        "Suspicious authentication activity detected"

    )


    db.add(incident)


    db.flush()



    # ======================
    # Evidence
    # ======================

    evidence = Evidence(

        incident_id=incident.id,

        username="administrator",

        evidence_type=
        "LOGIN_ACTIVITY",

        snapshot_json=
        """
        {
          "event":"failed login burst",
          "count":15,
          "source_ip":"192.168.1.50"
        }
        """,

        sha256_hash=
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    )


    db.add(evidence)



    db.commit()


    print(
        "Demo data inserted"
    )


    from app.modules.blockchain.service import BlockchainService


    BlockchainService.create_block(

        db=db,

        evidence_id=evidence.id,

        evidence_hash=evidence.sha256_hash

)



if __name__ == "__main__":

    seed()
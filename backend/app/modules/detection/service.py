from datetime import timedelta

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.failed_login_event import FailedLoginEvent
from app.models.alert import Alert


class DetectionService:


    @staticmethod
    def check_bruteforce(
        db: Session,
        username: str,
        source_ip: str
    ):


        count = (
            db.query(
                func.count(
                    FailedLoginEvent.id
                )
            )
            .filter(
                FailedLoginEvent.username == username,
                FailedLoginEvent.source_ip == source_ip,
                FailedLoginEvent.failed_time >= (
                    func.now()
                    -
                    timedelta(seconds=60)
                )
            )
            .scalar()
        )


        if count >= 5:

            alert = Alert(

                alert_type="BRUTE_FORCE_LOGIN",

                severity="HIGH",

                username=username,

                source_ip=source_ip,

                risk_score=80
            )


            db.add(alert)

            db.commit()


            return alert


        return None
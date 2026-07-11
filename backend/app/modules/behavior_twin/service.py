from collections import Counter
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.behavior_profile import BehaviorProfile
from app.models.login_event import LoginEvent
from app.repositories.behavior_profile_repository import (
    BehaviorProfileRepository,
)


class BehaviorTwinService:

    @staticmethod
    def build_profile(
        db: Session,
        username: str
    ) -> BehaviorProfile | None:

        events = (
            db.query(LoginEvent)
            .filter(LoginEvent.username == username)
            .order_by(LoginEvent.login_time.asc())
            .all()
        )

        if not events:
            return None

        average_login_hour = (
            sum(
                event.login_time.hour
                + event.login_time.minute / 60
                for event in events
            )
            / len(events)
        )

        ip_counter = Counter(
            event.source_ip
            for event in events
        )

        common_source_ip = ip_counter.most_common(1)[0][0]

        first_login_at = events[0].login_time
        last_login_at = events[-1].login_time

        profile = BehaviorProfileRepository.get_by_username(
            db=db,
            username=username
        )

        if profile is None:
            profile = BehaviorProfile(
                username=username,
                avg_login_hour=round(average_login_hour, 2),
                total_logins=len(events),
                common_source_ip=common_source_ip,
                first_login_at=first_login_at,
                last_login_at=last_login_at,
                last_updated=datetime.utcnow()
            )

            return BehaviorProfileRepository.create(
                db=db,
                profile=profile
            )

        profile.avg_login_hour = round(average_login_hour, 2)
        profile.total_logins = len(events)
        profile.common_source_ip = common_source_ip
        profile.first_login_at = first_login_at
        profile.last_login_at = last_login_at
        profile.last_updated = datetime.utcnow()

        return BehaviorProfileRepository.update(
            db=db,
            profile=profile
        )

    @staticmethod
    def get_profile(
        db: Session,
        username: str
    ) -> BehaviorProfile | None:

        return BehaviorProfileRepository.get_by_username(
            db=db,
            username=username
        )
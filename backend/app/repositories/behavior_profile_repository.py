from sqlalchemy.orm import Session

from app.models.behavior_profile import BehaviorProfile


class BehaviorProfileRepository:

    @staticmethod
    def get_by_username(
        db: Session,
        username: str
    ) -> BehaviorProfile | None:
        return (
            db.query(BehaviorProfile)
            .filter(BehaviorProfile.username == username)
            .first()
        )

    @staticmethod
    def create(
        db: Session,
        profile: BehaviorProfile
    ) -> BehaviorProfile:
        db.add(profile)
        db.commit()
        db.refresh(profile)

        return profile

    @staticmethod
    def update(
        db: Session,
        profile: BehaviorProfile
    ) -> BehaviorProfile:
        db.add(profile)
        db.commit()
        db.refresh(profile)

        return profile
from sqlalchemy.orm import Session

from app.models.incident_event import IncidentEvent



class IncidentTimelineService:


    @staticmethod
    def create_event(
        db: Session,
        incident_id: int,
        event_type: str,
        description: str,
        actor_type="SYSTEM",
        actor_name=None,
        old_status=None,
        new_status=None,
        event_metadata=None
    ):


        event = IncidentEvent(

            incident_id=incident_id,

            event_type=event_type,

            actor_type=actor_type,

            actor_name=actor_name,

            description=description,

            old_status=old_status,

            new_status=new_status,

            event_metadata=event_metadata

        )


        db.add(event)

        db.commit()

        db.refresh(event)


        return event




    @staticmethod
    def get_timeline(
        db: Session,
        incident_id: int
    ):


        return (

            db.query(
                IncidentEvent
            )

            .filter(
                IncidentEvent.incident_id
                ==
                incident_id
            )

            .order_by(
                IncidentEvent.created_at.asc()
            )

            .all()

        )
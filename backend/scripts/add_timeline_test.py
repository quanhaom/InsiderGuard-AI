from app.db.session import SessionLocal

from app.modules.incidents.timeline_service import (
    IncidentTimelineService
)


db = SessionLocal()


IncidentTimelineService.create_event(
    db=db,
    incident_id=4,
    event_type="CREATED",
    description="Incident created from security alert"
)


IncidentTimelineService.create_event(
    db=db,
    incident_id=4,
    event_type="STATUS_CHANGE",
    description="Status changed OPEN -> INVESTIGATING",
    old_status="OPEN",
    new_status="INVESTIGATING"
)


db.close()


print("Timeline added")
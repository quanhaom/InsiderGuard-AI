from app.db.base import Base
from app.db.session import engine

from app.models.user import User
from app.models.login_event import LoginEvent
from app.models.behavior_profile import BehaviorProfile
from app.models.risk_assessment import RiskAssessment
from app.models.incident import Incident
from app.models.raw_windows_event import RawWindowsEvent
from app.models.failed_login_event import FailedLoginEvent

def init_db():
    Base.metadata.create_all(bind=engine)
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully")    
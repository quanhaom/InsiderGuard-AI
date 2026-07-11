from app.db.base import Base
from app.db.session import engine
from app.models.risk_assessment import RiskAssessment
# Import ALL models trước create_all
from app.models.user import User
from app.models.login_event import LoginEvent
from app.models.behavior_profile import BehaviorProfile


def init_db():
    Base.metadata.create_all(bind=engine)
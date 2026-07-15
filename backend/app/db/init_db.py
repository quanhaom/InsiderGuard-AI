from app.db.base import Base
from app.db.session import engine
from app.models.device import Device
from app.models.alert import Alert
from app.models.behavior_profile import BehaviorProfile
from app.models.blockchain_block import BlockchainBlock
from app.models.evidence import Evidence
from app.models.failed_login_event import FailedLoginEvent
from app.models.incident import Incident
from app.models.investigation_report import InvestigationReport
from app.models.login_event import LoginEvent
from app.models.raw_windows_event import RawWindowsEvent
from app.models.risk_assessment import RiskAssessment
from app.models.user import User


def init_db() -> None:
    Base.metadata.create_all(
        bind=engine,
        checkfirst=True,
    )


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully")
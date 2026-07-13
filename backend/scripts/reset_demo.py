from app.db.session import SessionLocal

from app.models.blockchain_block import BlockchainBlock
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.failed_login_event import FailedLoginEvent
from app.models.risk_assessment import RiskAssessment


db = SessionLocal()


for model in [
    BlockchainBlock,
    Evidence,
    Incident,
    Alert,
    FailedLoginEvent,
    RiskAssessment
]:
    db.query(model).delete()


db.commit()

print("Database cleaned")
from datetime import UTC, datetime, timedelta
import json

from app.db.session import SessionLocal
from app.models.alert import Alert
from app.models.blockchain_block import BlockchainBlock
from app.models.device import Device
from app.models.evidence import Evidence
from app.models.failed_login_event import FailedLoginEvent
from app.models.incident import Incident
from app.models.risk_assessment import RiskAssessment
from app.models.user import User
from app.modules.blockchain.service import BlockchainService


DEMO_EVIDENCE_HASH = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def utc_now_naive() -> datetime:
    """
    PostgreSQL columns currently use
    TIMESTAMP WITHOUT TIME ZONE.

    Generate UTC time and remove timezone
    information for compatibility.
    """
    return datetime.now(UTC).replace(
        tzinfo=None
    )


def seed_users(db) -> None:
    demo_users = [
        {
            "username": "administrator",
            "department": "Security",
            "role": "Administrator",
        },
        {
            "username": "finance.user",
            "department": "Finance",
            "role": "Employee",
        },
        {
            "username": "hr.user",
            "department": "Human Resources",
            "role": "Employee",
        },
    ]

    for item in demo_users:
        existing_user = (
            db.query(User)
            .filter(
                User.username
                == item["username"]
            )
            .first()
        )

        if existing_user is None:
            db.add(
                User(**item)
            )


def seed_devices(db) -> None:
    demo_devices = [
        {
            "hostname": "FIN-PC-01",
            "ip_address": "192.168.1.21",
            "mac_address": (
                "00:11:22:33:44:01"
            ),
            "os_name": "Windows 11 Pro",
            "os_version": "23H2",
            "owner_username": "finance.user",
            "agent_id": "agent-fin-pc-01",
            "collector_version": "1.0.0",
            "status": "ONLINE",
        },
        {
            "hostname": "HR-PC-02",
            "ip_address": "192.168.1.32",
            "mac_address": (
                "00:11:22:33:44:02"
            ),
            "os_name": "Windows 10 Pro",
            "os_version": "22H2",
            "owner_username": "hr.user",
            "agent_id": "agent-hr-pc-02",
            "collector_version": "1.0.0",
            "status": "OFFLINE",
        },
        {
            "hostname": "ADMIN-LAPTOP",
            "ip_address": "192.168.1.10",
            "mac_address": (
                "00:11:22:33:44:03"
            ),
            "os_name": "Windows 11 Pro",
            "os_version": "24H2",
            "owner_username": "administrator",
            "agent_id": (
                "agent-admin-laptop"
            ),
            "collector_version": "1.0.0",
            "status": "ONLINE",
        },
    ]

    for item in demo_devices:
        existing_device = (
            db.query(Device)
            .filter(
                Device.hostname
                == item["hostname"]
            )
            .first()
        )

        if existing_device is None:
            db.add(
                Device(**item)
            )
        else:
            # Đồng bộ lại thông tin demo
            # khi chạy seed nhiều lần.
            existing_device.ip_address = (
                item["ip_address"]
            )
            existing_device.mac_address = (
                item["mac_address"]
            )
            existing_device.os_name = (
                item["os_name"]
            )
            existing_device.os_version = (
                item["os_version"]
            )
            existing_device.owner_username = (
                item["owner_username"]
            )
            existing_device.agent_id = (
                item["agent_id"]
            )
            existing_device.collector_version = (
                item["collector_version"]
            )
            existing_device.status = (
                item["status"]
            )


def seed_failed_logins(db) -> None:
    existing_count = (
        db.query(FailedLoginEvent)
        .filter(
            FailedLoginEvent.username.in_(
                [
                    "administrator",
                    "admin",
                ]
            )
        )
        .count()
    )

    # Không chèn lại các sự kiện demo
    # nếu đã có dữ liệu.
    if existing_count > 0:
        return

    now = utc_now_naive()

    failed_events = [
        FailedLoginEvent(
            username="administrator",
            source_ip="192.168.1.50",
            failure_reason="Bad password",
            status="FAILED",
            sub_status="0xC000006A",
            failed_time=now,
        ),
        FailedLoginEvent(
            username="administrator",
            source_ip="192.168.1.50",
            failure_reason="Bad password",
            status="FAILED",
            sub_status="0xC000006A",
            failed_time=(
                now
                - timedelta(minutes=1)
            ),
        ),
        FailedLoginEvent(
            username="admin",
            source_ip="10.0.0.25",
            failure_reason="Unknown user",
            status="FAILED",
            sub_status="0xC0000064",
            failed_time=(
                now
                - timedelta(minutes=2)
            ),
        ),
    ]

    db.add_all(failed_events)


def get_or_create_risk(db):
    risk = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.username
            == "administrator",
            RiskAssessment.risk_score
            == 92,
        )
        .order_by(
            RiskAssessment.id.asc()
        )
        .first()
    )

    if risk is None:
        risk = RiskAssessment(
            username="administrator",
            risk_score=92,
            severity="HIGH",
            reason=(
                "Multiple failed login "
                "attempts followed by "
                "successful login"
            ),
        )

        db.add(risk)
        db.flush()

    return risk


def get_or_create_alert(db):
    alert = (
        db.query(Alert)
        .filter(
            Alert.username
            == "administrator",
            Alert.alert_type
            == "BRUTE_FORCE",
        )
        .order_by(
            Alert.id.asc()
        )
        .first()
    )

    if alert is None:
        alert = Alert(
            username="administrator",
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            risk_score=92,
            reason=(
                "Multiple failed "
                "authentication attempts "
                "detected"
            ),
        )

        db.add(alert)
        db.flush()

    return alert


def get_or_create_incident(
    db,
    alert: Alert,
):
    incident = (
        db.query(Incident)
        .filter(
            Incident.alert_id == alert.id,
            Incident.username
            == "administrator",
            Incident.title
            == (
                "Possible Account "
                "Compromise"
            ),
        )
        .order_by(
            Incident.id.asc()
        )
        .first()
    )

    if incident is None:
        incident = Incident(
            alert_id=alert.id,
            username="administrator",
            title=(
                "Possible Account "
                "Compromise"
            ),
            severity="HIGH",
            status="OPEN",
            description=(
                "Suspicious authentication "
                "activity detected"
            ),
        )

        db.add(incident)
        db.flush()

    return incident


def get_or_create_evidence(
    db,
    incident: Incident,
):
    evidence = (
        db.query(Evidence)
        .filter(
            Evidence.sha256_hash
            == DEMO_EVIDENCE_HASH
        )
        .first()
    )

    if evidence is None:
        snapshot = {
            "event": "failed login burst",
            "count": 15,
            "source_ip": "192.168.1.50",
            "username": "administrator",
            "incident_id": incident.id,
        }

        evidence = Evidence(
            incident_id=incident.id,
            username="administrator",
            evidence_type=(
                "LOGIN_ACTIVITY"
            ),
            snapshot_json=json.dumps(
                snapshot,
                ensure_ascii=False,
                indent=2,
            ),
            sha256_hash=(
                DEMO_EVIDENCE_HASH
            ),
        )

        db.add(evidence)
        db.flush()

    return evidence


def create_block_if_missing(
    db,
    evidence: Evidence,
) -> None:
    existing_block = (
        db.query(BlockchainBlock)
        .filter(
            BlockchainBlock.evidence_id
            == evidence.id
        )
        .first()
    )

    if existing_block is not None:
        return

    BlockchainService.create_block(
        db=db,
        evidence_id=evidence.id,
        evidence_hash=(
            evidence.sha256_hash
        ),
    )


def seed() -> None:
    db = SessionLocal()

    try:
        seed_users(db)
        seed_devices(db)
        seed_failed_logins(db)

        get_or_create_risk(db)

        alert = get_or_create_alert(db)

        incident = get_or_create_incident(
            db=db,
            alert=alert,
        )

        evidence = get_or_create_evidence(
            db=db,
            incident=incident,
        )

        # Flush trước để đảm bảo tất cả
        # entity đã có ID.
        db.flush()

        create_block_if_missing(
            db=db,
            evidence=evidence,
        )

        db.commit()

        print(
            "Demo data inserted successfully"
        )

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    seed()
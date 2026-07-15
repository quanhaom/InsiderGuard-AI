from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.device import Device
from sqlalchemy import func

from app.models.incident import Incident
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.models.user import User    

class EntityService:

    @staticmethod
    def _resolve_status(
        device: Device
    ) -> str:
        if device.status in {
            "INACTIVE",
            "DISABLED",
        }:
            return device.status

        offline_threshold = (
            datetime.utcnow()
            - timedelta(minutes=5)
        )

        if (
            device.last_seen
            and device.last_seen
            >= offline_threshold
        ):
            return "ONLINE"

        return "OFFLINE"

    @classmethod
    def get_user(
        cls,
        db: Session,
        user_id: int,
    ) -> dict[str, Any] | None:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        if user is None:
            return None

        devices = (
            db.query(Device)
            .filter(
                Device.owner_username
                == user.username
            )
            .order_by(
                Device.last_seen.desc()
            )
            .all()
        )

        incidents = (
            db.query(Incident)
            .filter(
                Incident.username
                == user.username
            )
            .order_by(
                Incident.created_at.desc()
            )
            .limit(20)
            .all()
        )

        risk_assessments = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.username
                == user.username
            )
            .order_by(
                RiskAssessment.created_at.desc()
            )
            .limit(20)
            .all()
        )

        recent_logins = (
            db.query(LoginEvent)
            .filter(
                LoginEvent.username
                == user.username
            )
            .order_by(
                LoginEvent.login_time.desc()
            )
            .limit(20)
            .all()
        )

        latest_risk = (
            risk_assessments[0]
            if risk_assessments
            else None
        )

        return {
            "id": user.id,
            "username": user.username,
            "department": user.department,
            "role": user.role,

            "current_risk": {
                "score": (
                    latest_risk.risk_score
                    if latest_risk
                    else 0
                ),
                "severity": (
                    latest_risk.severity
                    if latest_risk
                    else "LOW"
                ),
                "reason": (
                    latest_risk.reason
                    if latest_risk
                    else None
                ),
                "created_at": (
                    latest_risk.created_at
                    if latest_risk
                    else None
                ),
            },

            "devices": [
                {
                    "id": device.id,
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "os_name": device.os_name,
                    "status": cls._resolve_status(
                        device
                    ),
                    "last_seen": device.last_seen,
                }
                for device in devices
            ],

            "incidents": [
                {
                    "id": incident.id,
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                    "created_at": incident.created_at,
                    "closed_at": incident.closed_at,
                }
                for incident in incidents
            ],

            "risk_history": [
                {
                    "id": risk.id,
                    "risk_score": risk.risk_score,
                    "severity": risk.severity,
                    "reason": risk.reason,
                    "created_at": risk.created_at,
                }
                for risk in risk_assessments
            ],

            "recent_logins": [
                {
                    "id": login.id,
                    "ip_address": login.ip_address,
                    "login_time": login.login_time,
                }
                for login in recent_logins
            ],
        }



    @classmethod
    def list_users(
        cls,
        db: Session,
        *,
        page: int = 1,
        page_size: int = 20,
        search: str | None = None,
        department: str | None = None,
        role: str | None = None,
    ) -> dict[str, Any]:
        query = db.query(User)

        if search:
            keyword = f"%{search.strip()}%"

            query = query.filter(
                User.username.ilike(keyword)
            )

        if department:
            query = query.filter(
                User.department.ilike(
                    f"%{department.strip()}%"
                )
            )

        if role:
            query = query.filter(
                User.role.ilike(
                    f"%{role.strip()}%"
                )
            )

        total = query.count()

        users = (
            query
            .order_by(User.username.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        items = []

        for user in users:
            device_count = (
                db.query(func.count(Device.id))
                .filter(
                    Device.owner_username
                    == user.username
                )
                .scalar()
                or 0
            )

            incident_count = (
                db.query(func.count(Incident.id))
                .filter(
                    Incident.username
                    == user.username
                )
                .scalar()
                or 0
            )

            unresolved_incident_count = (
                db.query(func.count(Incident.id))
                .filter(
                    Incident.username
                    == user.username,
                    Incident.status.in_(
                        [
                            "OPEN",
                            "IN_PROGRESS",
                            "CONTAINED",
                        ]
                    ),
                )
                .scalar()
                or 0
            )

            latest_risk = (
                db.query(RiskAssessment)
                .filter(
                    RiskAssessment.username
                    == user.username
                )
                .order_by(
                    RiskAssessment.created_at.desc()
                )
                .first()
            )

            items.append(
                {
                    "id": user.id,
                    "username": user.username,
                    "department": user.department,
                    "role": user.role,
                    "device_count": device_count,
                    "incident_count": incident_count,
                    "unresolved_incident_count": (
                        unresolved_incident_count
                    ),
                    "risk_score": (
                        latest_risk.risk_score
                        if latest_risk
                        else 0
                    ),
                    "risk_severity": (
                        latest_risk.severity
                        if latest_risk
                        else "LOW"
                    ),
                }
            )

        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (
                total + page_size - 1
            ) // page_size,
        }

    @classmethod
    def list_devices(
        cls,
        db: Session,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        owner_username: str | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        query = db.query(Device)

        if owner_username:
            query = query.filter(
                Device.owner_username.ilike(
                    f"%{owner_username.strip()}%"
                )
            )

        if search:
            keyword = (
                f"%{search.strip()}%"
            )

            query = query.filter(
                Device.hostname.ilike(keyword)
                | Device.ip_address.ilike(keyword)
                | Device.mac_address.ilike(keyword)
                | Device.agent_id.ilike(keyword)
            )

        total = query.count()

        devices = (
            query
            .order_by(
                Device.last_seen.desc(),
                Device.id.desc(),
            )
            .offset(
                (page - 1) * page_size
            )
            .limit(page_size)
            .all()
        )

        items = []

        for device in devices:
            resolved_status = (
                cls._resolve_status(device)
            )

            if (
                status
                and resolved_status
                != status.upper()
            ):
                continue

            items.append(
                {
                    "id": device.id,
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "mac_address": device.mac_address,
                    "os_name": device.os_name,
                    "os_version": device.os_version,
                    "owner_username": (
                        device.owner_username
                    ),
                    "agent_id": device.agent_id,
                    "collector_version": (
                        device.collector_version
                    ),
                    "status": resolved_status,
                    "first_seen": device.first_seen,
                    "last_seen": device.last_seen,
                }
            )

        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (
                total + page_size - 1
            ) // page_size,
        }

    @classmethod
    def get_device(
        cls,
        db: Session,
        device_id: int,
    ) -> dict[str, Any] | None:
        device = (
            db.query(Device)
            .filter(
                Device.id == device_id
            )
            .first()
        )

        if device is None:
            return None

        return {
            "id": device.id,
            "hostname": device.hostname,
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "os_name": device.os_name,
            "os_version": device.os_version,
            "owner_username": (
                device.owner_username
            ),
            "agent_id": device.agent_id,
            "collector_version": (
                device.collector_version
            ),
            "status": cls._resolve_status(
                device
            ),
            "first_seen": device.first_seen,
            "last_seen": device.last_seen,
        }
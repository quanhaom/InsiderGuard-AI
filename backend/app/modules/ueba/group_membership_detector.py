from sqlalchemy.orm import Session

from app.models.alert import Alert

from app.modules.incidents.service import (
    IncidentService,
)

from app.modules.incidents.timeline_service import (
    IncidentTimelineService,
)


class GroupMembershipDetector:

    CRITICAL_GROUPS = {
        "domain admins",
        "enterprise admins",
        "schema admins",
    }

    HIGH_RISK_GROUPS = {
        "administrators",
        "backup operators",
        "account operators",
        "server operators",
        "print operators",
        "dnsadmins",
        "group policy creator owners",
        "remote desktop users",
        "remote management users",
    }

    SUSPICIOUS_ACTORS = {
        "unknown",
        "anonymous logon",
        "-",
        "",
    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed,
    ) -> dict:
        actor_username = (
            parsed.actor_username
            or "unknown"
        )

        member_username = (
            parsed.member_username
            or "unknown"
        )

        group_name = (
            parsed.group_name
            or "unknown"
        )

        normalized_group = (
            group_name
            .strip()
            .lower()
        )

        normalized_actor = (
            actor_username
            .strip()
            .lower()
        )

        reasons: list[str] = []

        risk_score = 35

        reasons.append(
            f"User {member_username} was added "
            f"to security group {group_name}"
        )

        if (
            normalized_group
            in cls.CRITICAL_GROUPS
        ):
            risk_score += 50

            reasons.append(
                "The target group grants "
                "domain-wide administrative privileges"
            )

        elif (
            normalized_group
            in cls.HIGH_RISK_GROUPS
        ):
            risk_score += 35

            reasons.append(
                "The target group grants "
                "elevated or remote-access privileges"
            )

        if (
            normalized_actor
            in cls.SUSPICIOUS_ACTORS
        ):
            risk_score += 15

            reasons.append(
                "The actor performing the group "
                "change could not be identified"
            )

        if (
            member_username.strip().lower()
            == actor_username.strip().lower()
        ):
            risk_score += 10

            reasons.append(
                "The actor added their own account "
                "to the privileged group"
            )

        risk_score = min(
            risk_score,
            100,
        )

        if risk_score >= 85:
            severity = "CRITICAL"

        elif risk_score >= 65:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        detected = (
            normalized_group
            in cls.CRITICAL_GROUPS
            or normalized_group
            in cls.HIGH_RISK_GROUPS
        )

        if not detected:
            return {
                "detected": False,
                "risk_score": risk_score,
                "severity": severity,
                "actor_username": (
                    actor_username
                ),
                "member_username": (
                    member_username
                ),
                "group_name": (
                    group_name
                ),
            }

        reason = "; ".join(
            reasons
        )

        alert = Alert(
            username=member_username,

            alert_type=(
                "PRIVILEGED_GROUP_MEMBERSHIP"
            ),

            severity=severity,

            risk_score=risk_score,

            reason=reason,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        incident = (
            IncidentService
            .create_from_alert(
                db=db,
                alert=alert,
            )
        )

        if incident is not None:
            IncidentTimelineService.create_event(
                db=db,

                incident_id=incident.id,

                event_type=(
                    "PRIVILEGED_GROUP_MEMBERSHIP"
                ),

                actor_type="SYSTEM",

                description=(
                    "Windows Event 4728 detected "
                    "a member being added to "
                    "a privileged security group"
                ),

                event_metadata={
                    "actor_username": (
                        actor_username
                    ),

                    "member_username": (
                        member_username
                    ),

                    "member_sid": (
                        parsed.member_sid
                    ),

                    "group_name": (
                        group_name
                    ),

                    "group_domain": (
                        parsed.group_domain
                    ),

                    "group_sid": (
                        parsed.group_sid
                    ),

                    "computer": (
                        parsed.computer
                    ),

                    "source_ip": (
                        parsed.source_ip
                    ),

                    "risk_score": (
                        risk_score
                    ),

                    "severity": (
                        severity
                    ),
                },
            )

        return {
            "detected": True,

            "risk_score": risk_score,

            "severity": severity,

            "actor_username": (
                actor_username
            ),

            "member_username": (
                member_username
            ),

            "group_name": (
                group_name
            ),

            "alert_id": alert.id,

            "incident_id": (
                incident.id
                if incident is not None
                else None
            ),

            "incident_created": (
                incident is not None
            ),
        }
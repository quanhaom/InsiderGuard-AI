from sqlalchemy.orm import Session
from app.modules.parsers.parser_4672 import (
    Parser4672,
)
from app.modules.parsers.parser_4720 import (
    Parser4720,
)

from app.modules.ueba.account_creation_detector import (
    AccountCreationDetector,
)
from app.modules.ueba.privilege_detector import (
    PrivilegeDetector,
)
from app.models.raw_windows_event import (
    RawWindowsEvent,
)
from app.modules.parsers.parser_4688 import (
    Parser4688,
)

from app.modules.ueba.process_detector import (
    SuspiciousProcessDetector,
)
from app.modules.parsers.parser_4624 import (
    Parser4624,
)

from app.modules.parsers.parser_4625 import (
    Parser4625,
)

from app.modules.ueba.failed_login_detector import (
    FailedLoginDetector,
)

from app.modules.events.service import (
    EventService,
)

from app.modules.behavior_profile.service import (
    BehaviorProfileService,
)
from app.modules.parsers.parser_4728 import (
    Parser4728,
)

from app.modules.ueba.group_membership_detector import (
    GroupMembershipDetector,
)
from app.modules.windows_events.normalizer import (
    WindowsNormalizer,
)



class WindowsEventService:


    PARSERS = {

        4624: Parser4624(),

        4625: Parser4625(),

        4672: Parser4672(),
        
        4688: Parser4688(),

        4720: Parser4720(),

        4728: Parser4728(),
    }


    @classmethod
    def process_event(
        cls,
        db: Session,
        event: RawWindowsEvent
    ):


        parser = cls.PARSERS.get(
            event.event_id
        )


        if parser is None:

            return None



        parsed = parser.parse(
            db=db,
            event=event
        )



        # =========================
        # NORMALIZE WINDOWS EVENT
        # =========================

        normalized_event = (
            WindowsNormalizer.save(
                db=db,
                raw_event=event,
                parsed=parsed
            )
        )



        # =========================
        # EVENT 4624
        # SUCCESS LOGIN
        # =========================

        if event.event_id == 4624:


            login_event = (
                EventService
                .create_login_event(
                    db=db,
                    payload=parsed
                )
            )



            BehaviorProfileService.build_profile(
                db=db,
                username=parsed.username
            )



            return {

                "normalized_event_id":
                    normalized_event.id,

                "login_event_id":
                    login_event.id,

            }





        # =========================
        # EVENT 4625
        # FAILED LOGIN
        # =========================

        if event.event_id == 4625:


            from app.modules.failed_login_events.service import (
                FailedLoginEventService,
            )



            failed_event = (
                FailedLoginEventService.create(
                    db=db,
                    payload=parsed,
                )
            )



            detection_result = (
                FailedLoginDetector.evaluate(
                    db=db,
                    event=failed_event,
                )
            )



            BehaviorProfileService.build_profile(
                db=db,
                username=parsed.username,
            )



            return {

                "normalized_event_id":
                    normalized_event.id,


                "failed_login_event_id":
                    failed_event.id,


                "detection":
                    detection_result,

            }
        

        # =========================

        # EVENT 4672
        # SPECIAL PRIVILEGES ASSIGNED
        # =========================
        if event.event_id == 4672:

            detection = (
                PrivilegeDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {

                "normalized_event_id":
                    normalized_event.id,

                "detection":
                    detection,

            }
        

        # =========================
        # EVENT 4688
        # PROCESS CREATED
        # =========================
        # =========================
# EVENT 4688
# PROCESS CREATION
# =========================

        if event.event_id == 4688:
            detection_result = (
                SuspiciousProcessDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "normalized_event_id": (
                    normalized_event.id
                ),

                "detection": (
                    detection_result
                ),
            }
        
        # =========================
# EVENT 4720
# USER ACCOUNT CREATED
# =========================

        if event.event_id == 4720:
            detection_result = (
                AccountCreationDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "normalized_event_id": (
                    normalized_event.id
                ),

                "detection": (
                    detection_result
                ),
            }
        

        # =========================
        # EVENT 4728
        # PRIVILEGED GROUP MEMBERSHIP
        # =========================

        if event.event_id == 4728:
            detection_result = (
                GroupMembershipDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "normalized_event_id": (
                    normalized_event.id
                ),

                "detection": (
                    detection_result
                ),
            }
from app.modules.parsers.parser_4624 import (
    Parser4624,
)
from app.modules.parsers.parser_4625 import (
    Parser4625,
)
from app.modules.parsers.parser_4672 import (
    Parser4672,
)
from app.modules.parsers.sysmon_parser_3 import (
    SysmonParser3,
)
from app.modules.parsers.parser_4688 import (
    Parser4688,
)
from app.modules.parsers.parser_4720 import (
    Parser4720,
)
from app.modules.parsers.parser_4728 import (
    Parser4728,
)
from app.modules.parsers.sysmon_parser_1 import (
    SysmonParser1,
)
from app.modules.parsers.sysmon_parser_11 import (
    SysmonParser11,
)
from app.modules.parsers.sysmon_parser_11 import (
    SysmonParser3,
)

from app.modules.windows_events.parser_registry import (
    ParserRegistry,
)


SECURITY_PROVIDER = (
    "microsoft-windows-security-auditing"
)

SYSMON_PROVIDER = (
    "microsoft-windows-sysmon"
)


def register_windows_pipeline() -> None:

    ParserRegistry.register(
        SECURITY_PROVIDER,
        4624,
        Parser4624(),
    )

    ParserRegistry.register(
        SYSMON_PROVIDER,
        3,
        SysmonParser3(),
    )
    ParserRegistry.register(
        SECURITY_PROVIDER,
        4625,
        Parser4625(),
    )

    ParserRegistry.register(
        SECURITY_PROVIDER,
        4672,
        Parser4672(),
    )

    ParserRegistry.register(
        SECURITY_PROVIDER,
        4688,
        Parser4688(),
    )

    ParserRegistry.register(
        SECURITY_PROVIDER,
        4720,
        Parser4720(),
    )

    ParserRegistry.register(
        SECURITY_PROVIDER,
        4728,
        Parser4728(),
    )

    ParserRegistry.register(
        SYSMON_PROVIDER,
        1,
        SysmonParser1(),
    )

    ParserRegistry.register(
        SYSMON_PROVIDER,
        3,
        SysmonParser3
    )

    ParserRegistry.register(
        SYSMON_PROVIDER,
        11,
        SysmonParser11
    )
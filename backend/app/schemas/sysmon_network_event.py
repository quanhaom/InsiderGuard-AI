from datetime import datetime

from pydantic import BaseModel


class SysmonNetworkEventData(BaseModel):
    event_id: int = 3
    provider: str = "Microsoft-Windows-Sysmon"

    utc_time: datetime | None = None

    process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
    user: str | None = None

    protocol: str | None = None
    initiated: bool | None = None

    source_is_ipv6: bool | None = None
    source_ip: str | None = None
    source_hostname: str | None = None
    source_port: int | None = None
    source_port_name: str | None = None

    destination_is_ipv6: bool | None = None
    destination_ip: str | None = None
    destination_hostname: str | None = None
    destination_port: int | None = None
    destination_port_name: str | None = None

    computer: str | None = None

    action: str = "network_connection"
    category: str = "network"
    severity: str = "info"
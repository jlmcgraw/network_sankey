"""Model definitions for network packet data."""

import logging
from dataclasses import dataclass
from enum import Enum

# Do this to suppress warnings when loading scapy module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

MacAddress = str
IPv4Address = str
IPv6Address = str
IpAddress = IPv4Address | IPv6Address
Interface = str
Length = int

IpAddressInterfaceDict = dict[IpAddress, Interface]
MacAddressInterfaceDict = dict[MacAddress, Interface]


@dataclass
class FrameData:
    """Normalized packet data for Sankey diagrams."""

    timestamp: str | None = None
    source_mac: str | None = None
    destination_mac: str | None = None
    type: str | None = None
    length: int | None = None
    direction: str | None = None
    scope: str | None = None
    frames: int | None = None
    l3_source: str | None = None
    l3_destination: str | None = None
    l3_type: str | None = None
    l4_source: str | None = None
    l4_destination: str | None = None
    highest_protocol: str | None = None


class Scope(Enum):
    """Possible scope of a frame."""

    BROADCAST = "broadcast"
    MULTICAST = "multicast"
    UNICAST = "unicast"


class Direction(Enum):
    """Frame directions relative to the host."""

    TRANSMIT = "transmit"
    RECEIVE = "receive"


ethernet_type_to_protocol_lookup = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x9104: "Eero",
    # Add more types as needed
}

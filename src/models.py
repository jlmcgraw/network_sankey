import logging
from dataclasses import dataclass
from enum import Enum
from typing import Union

# Do this to suppress warnings when loading scapy module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

MacAddress = str
IPv4Address = str
IPv6Address = str
IpAddress = Union[IPv4Address, IPv6Address]
Interface = str
Length = int

IpAddressInterfaceDict = dict[IpAddress, Interface]
MacAddressInterfaceDict = dict[MacAddress, Interface]


@dataclass
class FrameData:
    timestamp: str = None
    source_mac: str = None
    destination_mac: str = None
    type: str = None
    length: int = None
    direction: str = None
    scope: str = None
    frames: int = None
    l3_source: str = None
    l3_destination: str = None
    l3_type: str = None
    l4_source: str = None
    l4_destination: str = None
    highest_protocol: str = None


class Scope(Enum):
    BROADCAST = "broadcast"
    MULTICAST = "multicast"
    UNICAST = "unicast"


class Direction(Enum):
    TRANSMIT = "transmit"
    RECEIVE = "receive"


ethernet_type_to_protocol_lookup = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x9104: "Eero",
    # Add more types as needed
}

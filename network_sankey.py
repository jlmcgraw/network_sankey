import argparse
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from itertools import pairwise
from typing import Union

import pandas as pd
import plotly.graph_objects as go
import scapy.packet

# Do this to suppress warnings when loading scapy module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import get_if_addr, get_if_list, get_if_hwaddr, sniff
from scapy.all import rdpcap, wrpcapng
from tqdm import tqdm

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


ethernet_type_to_protocol = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x9104: "Eero",
    # Add more types as needed
}


def determine_frame_scope(frame: scapy.packet.Packet) -> Enum:
    """
    Determine whether frame is broadcast, multicast, or unicast
    :param frame:
    :return:
    """
    if not frame.haslayer("Ether"):
        print(f"{frame=}")
        raise ValueError("Non-Ethernet frame")

    dst_mac = frame.dst
    if dst_mac == "ff:ff:ff:ff:ff:ff":
        return Scope.BROADCAST
    elif int(dst_mac.split(":")[0], 16) & 1:
        return Scope.MULTICAST

    return Scope.UNICAST


def determine_frame_direction(
    frame: scapy.packet.Packet, my_mac_addresses: MacAddressInterfaceDict
) -> Enum:
    if frame.src in my_mac_addresses:
        return Direction.TRANSMIT
    return Direction.RECEIVE


def create_mac_to_interface_mapping() -> MacAddressInterfaceDict:
    """
    Create a mac->interface mapping dict
    :return:
    """
    mac_addresses_mapping_dict: MacAddressInterfaceDict = dict()

    for interface in get_if_list():
        try:
            mac_address = get_if_hwaddr(interface)
            # Filtering out interfaces that might not have a MAC address
            if mac_address != "00:00:00:00:00:00":
                mac_addresses_mapping_dict[mac_address] = interface
        except ValueError:
            # This handles cases where an interface might not have a MAC address
            pass

    return mac_addresses_mapping_dict


def create_ip_to_interface_mapping() -> IpAddressInterfaceDict:
    """
    Create an ip->interface mapping dict
    :return:
    """
    ip_to_interface_dict: IpAddressInterfaceDict = dict()

    for interface in get_if_list():
        try:
            ip_address = get_if_addr(interface)
            # Filtering out interfaces that might not have an IP address assigned
            if ip_address != "0.0.0.0":
                ip_to_interface_dict[ip_address] = interface
        except ValueError:
            # This handles cases where an interface might not have an IP address
            pass

    return ip_to_interface_dict


def create_and_display_sankey_diagram(df: pd.DataFrame):
    """
    Using the dataframe, create inputs for the Sankey diagrams and then display them
    :param df:
    :return:
    """
    # I'd really like to be able to trace a flow from beginning to end
    #  ex: https://public.tableau.com/app/profile/actinvision/viz/SuperstoreSankeyShowcaseLOD/Sankey

    # data for which fields to use for the "path" when showing receive/transmit
    dir_path = {
        "receive": {
            "path": [
                "l4_source",
                "l3_type",
                "l3_source",
                "type",
                "source_mac",
                "destination_mac",
            ],
            "col": 1,
            "row": 1,
            "alignment": "right",
        },
        "transmit": {
            "path": [
                "source_mac",
                "destination_mac",
                "type",
                "l3_destination",
                "l3_type",
                "l4_destination",
            ],
            "col": 2,
            "row": 1,
            "alignment": "left",
        },
    }
    # The idea here is to do a groupby for each pair of columns from the "path" in order to create the
    # count for them (eg frames or bytes)
    for metric in ["length", "frames"]:
        for direction, values in dir_path.items():
            # Create the pairs from the list
            # eg [ A, B, C, D] -> (A,B ), (B,C), (C,D)
            path_pairs = list(pairwise(values["path"]))

            # Map each unique value of interesting fields to an index number to give to sankey
            all_nodes = pd.concat(
                [df[column_name] for column_name in values["path"]]
            ).unique()
            node_indices = {node: index for index, node in enumerate(all_nodes)}

            combined_df = pd.DataFrame()

            for source, target in path_pairs:
                agg_data = (
                    df.query(f'direction == "{direction}"')
                    .groupby(
                        [
                            source,
                            target,
                        ],
                        dropna=False,
                    )[metric]
                    .sum()
                    .reset_index()
                )

                # Apply mapping to the aggregated data
                # Avoid trying to look up cells that are None/NaN
                agg_data["SourceID"] = agg_data[source].apply(
                    lambda x: node_indices[x] if (pd.notnull(x)) else x
                )
                agg_data["TargetID"] = agg_data[target].apply(
                    lambda x: node_indices[x] if (pd.notnull(x)) else x
                )
                agg_data["Value"] = agg_data[metric].apply(lambda x: x)

                # Accumulate the dataframe
                combined_df = pd.concat([combined_df, agg_data])

            # Creating the Sankey diagram
            fig = go.Figure(
                data=[
                    go.Sankey(
                        node=dict(
                            pad=15,
                            thickness=20,
                            line=dict(color="black", width=0.5),
                            label=list(all_nodes),
                            align=values["alignment"],
                        ),
                        link=dict(
                            # indices of source nodes
                            source=combined_df["SourceID"],
                            # indices of source nodes
                            target=combined_df["TargetID"],
                            # values for each flow
                            value=combined_df["Value"],
                        ),
                    )
                ]
            )

            fig.update_layout(title_text=f"Network {direction} {metric}", font_size=10)
            fig.show()


# def try_sunburst(df, metric=None):
#     paths = ["destination_mac", "source_mac"]
#
#     res = list(pairwise(paths))
#     for source, target in res:
#         receive_data = (
#             df.groupby(
#                 [source, target],
#                 dropna=False,
#             )[metric]
#             .sum()
#             .reset_index()
#         )
#         print(receive_data)
#     # receive_data = (
#     #     df.query('direction == "receive"')
#     #     .groupby(
#     #         [
#     #             # "direction",
#     #             "source_mac",
#     #             "destination_mac",
#     #             "type",
#     #             # "scope",
#     #             "l3_source",
#     #             "l3_type",
#     #             "l4_source",
#     #         ],
#     #         dropna=False,
#     #     )["frames"]
#     #     .sum()
#     #     .reset_index()
#     # )
#     # transmit_data = (
#     #     df.query('direction == "transmit"')
#     #     .groupby(
#     #         [
#     #             # "direction",
#     #             "source_mac",
#     #             "destination_mac",
#     #             "type",
#     #             # "scope",
#     #             "l3_destination",
#     #             "l3_type",
#     #             "l4_destination",
#     #         ],
#     #         dropna=False,
#     #     )["frames"]
#     #     .sum()
#     #     .reset_index()
#     # )
#     #
#     # fig = px.sunburst(
#     #     receive_data,
#     #     path=[
#     #         "destination_mac",
#     #         "source_mac",
#     #         "type",
#     #         "l3_source",
#     #         "l3_type",
#     #         "l4_source",
#     #     ],
#     #     values="frames",
#     #     color="destination_mac",
#     # )
#     # fig = px.sunburst(
#     #     transmit_data,
#     #     path=[
#     #         "source_mac",
#     #         "destination_mac",
#     #         "type",
#     #         "l3_destination",
#     #         "l3_type",
#     #         "l4_destination",
#     #     ],
#     #     values="frames",
#     #     color="source_mac",
#     # )
#     # fig = make_subplots(rows=1, cols=2)
#     # fig.add_trace([sunburst_1], row=1, col=1)
#     #
#     # fig.add_trace([sunburst_2], row=1, col=2)
#
#     # fig.show()


def construct_dataframe_from_capture(
    packets: scapy.all.PacketList,
    mac_address_to_interface_mapping: MacAddressInterfaceDict,
) -> pd.DataFrame:

    """
    Given the captured packets, construct and enrich a dataframe to be used as input for Sankey

    :param packets:
    :param mac_address_to_interface_mapping:
    :return:
    """
    # Layer 2
    data = []

    for packet in packets:
        frame_data = FrameData()
        l3_source = None
        l3_destination = None
        l3_type = None
        l4_source = None
        l4_destination = None
        # scapy.layers.inet.TCP
        # 'scapy.layers.inet6.
        # Extracting Layer 2 (Ethernet frame) information
        # print(packet.layers())

        # Layer 2
        if not packet.haslayer("Ether"):
            print(f"{packet=}")
            raise ValueError(f"Non-Ethernet frame: {packet}")
        ethernet_frame = packet.getlayer("Ether")
        ethernet_frame_type = f"{ethernet_frame.type:#06x}"
        ethernet_frame_type = ethernet_type_to_protocol.get(
            ethernet_frame.type, ethernet_frame_type
        )
        # print(f"{ethernet_frame_type=}")
        # Layer 3
        if packet.haslayer("IP"):
            l3_source = packet["IP"].src
            l3_destination = packet["IP"].dst
            l3_type = packet["IP"].proto
            # print(f"IP {l3_type=}")
            try:
                l3_type = packet["IP"].get_field("proto").i2s[l3_type]
                l3_type = l3_type.upper()
                # print(f"{l3_type=}")
            except AttributeError:
                pass
        elif packet.haslayer("IPv6"):
            l3_source = packet["IPv6"].src
            l3_destination = packet["IPv6"].dst
            l3_type = packet["IPv6"].nh
            # print(f"IPv6 {l3_type=}")
            try:
                l3_type = packet["IPv6"].get_field("nh").i2s[l3_type]
                l3_type = l3_type.upper()

                # print(f"{l3_type=}")
            except AttributeError:
                pass

        # Layer 4
        if packet.haslayer("UDP"):
            l4_source = packet["UDP"].sport
            l4_destination = packet["UDP"].dport
        elif packet.haslayer("TCP"):
            l4_source = packet["TCP"].sport
            l4_destination = packet["TCP"].dport

        packet_data = {
            "timestamp": packet.time,
            "source_mac": ethernet_frame.src,
            "destination_mac": ethernet_frame.dst,
            "type": ethernet_frame_type,
            "length": len(packet),
            # "interface": {my}
            "direction": f"{determine_frame_direction(packet, mac_address_to_interface_mapping).value}",
            "scope": f"{determine_frame_scope(packet).value}",
            "frames": 1,
            "l3_source": l3_source,
            "l3_destination": l3_destination,
            "l3_type": l3_type,
            "l4_source": l4_source,
            "l4_destination": l4_destination,
        }

        data.append(packet_data)

    df = pd.DataFrame(data)
    # df.fillna(value=np.nan, inplace=True)
    return df


def construct_dataframe_from_capture_using_tshark(
    packets: scapy.all.PacketList,
    mac_address_to_interface_mapping: MacAddressInterfaceDict,
) -> pd.DataFrame:
    """
    Given the captured packets, construct and enrich a dataframe to be used as input for Sankey

    :param packets:
    :param mac_address_to_interface_mapping:
    :return:
    """
    # Layer 2
    data = []


    for packet in packets:
        frame_data = FrameData()

        # Layer 2
        if not packet.haslayer("Ether"):
            print(f"{packet=}")
            raise ValueError(f"Non-Ethernet frame: {packet}")
        ethernet_frame = packet.getlayer("Ether")
        ethernet_frame_type = f"{ethernet_frame.type:#06x}"
        ethernet_frame_type = ethernet_type_to_protocol.get(
            ethernet_frame.type, ethernet_frame_type
        )
        # print(f"{ethernet_frame_type=}")
        # Layer 3
        if packet.haslayer("IP"):
            l3_source = packet["IP"].src
            l3_destination = packet["IP"].dst
            l3_type = packet["IP"].proto
            # print(f"IP {l3_type=}")
            try:
                l3_type = packet["IP"].get_field("proto").i2s[l3_type]
                l3_type = l3_type.upper()
                # print(f"{l3_type=}")
            except AttributeError:
                pass
        elif packet.haslayer("IPv6"):
            l3_source = packet["IPv6"].src
            l3_destination = packet["IPv6"].dst
            l3_type = packet["IPv6"].nh
            # print(f"IPv6 {l3_type=}")
            try:
                l3_type = packet["IPv6"].get_field("nh").i2s[l3_type]
                l3_type = l3_type.upper()

                # print(f"{l3_type=}")
            except AttributeError:
                pass

        # Layer 4
        if packet.haslayer("UDP"):
            l4_source = packet["UDP"].sport
            l4_destination = packet["UDP"].dport
        elif packet.haslayer("TCP"):
            l4_source = packet["TCP"].sport
            l4_destination = packet["TCP"].dport

        packet_data = {
            "timestamp": packet.time,
            "source_mac": ethernet_frame.src,
            "destination_mac": ethernet_frame.dst,
            "type": ethernet_frame_type,
            "length": len(packet),
            # "interface": {my}
            "direction": f"{determine_frame_direction(packet, mac_address_to_interface_mapping).value}",
            "scope": f"{determine_frame_scope(packet).value}",
            "frames": 1,
            "l3_source": l3_source,
            "l3_destination": l3_destination,
            "l3_type": l3_type,
            "l4_source": l4_source,
            "l4_destination": l4_destination,
        }

        data.append(packet_data)

    df = pd.DataFrame(data)
    # df.fillna(value=np.nan, inplace=True)
    return df


def parse_command_line_arguments():
    parser = argparse.ArgumentParser(
        description="A script to capture and display network traffic as a Sankey diagram"
    )
    parser.add_argument(
        "capture_file",
        nargs="?",
        default=None,
        help="Name of capture file to load instead of live traffic",
    )
    parser.add_argument(
        "--count", type=int, default=1_000, help="Number of packets to capture for live traffic"
    )
    parser.add_argument(
        "--interface", type=str, default="en0", help="Interface to use for capture for live traffic"
    )

    args = parser.parse_args()
    return args


def main():
    def packet_callback(packet):
        # This is the callback function executed for each packet captured
        # Update the tqdm progress bar by 1 for each packet
        pbar.update(1)
        # You can add more packet processing logic here

    args = parse_command_line_arguments()
    packet_capture_file = args.capture_file
    packet_count = args.count
    capture_interface = args.interface

    # List all IP addresses
    ip_to_interface_mapping_dict = create_ip_to_interface_mapping()

    # List all MAC addresses
    mac_addresses_mapping_dict = create_mac_to_interface_mapping()

    # Load packet capture or sniff traffic
    if packet_capture_file:
        print(f"Loading previously captured traffic from '{packet_capture_file}'")
        try:
            packets = rdpcap(packet_capture_file)
        except Exception as e:
            print(f"Unable to load packet capture '{packet_capture_file}': {e}")
            return 1
    else:
        print(f"Capturing {packet_count} packets from interface '{capture_interface}'")
        # Initialize a tqdm progress bar
        with tqdm(desc="Packets Captured", unit=" packets", total=packet_count) as pbar:
            # Capture packets
            packets = sniff(
                iface=capture_interface,
                # Use the callback to update progress bar
                prn=packet_callback,
                count=packet_count,
                # stop_filter=lambda x: pbar.n >= packet_count
            )

        # Get current date and time
        now = datetime.now()

        # Format the date and time as a string, for example "2024-03-06"
        formatted_date = now.strftime("%Y-%m-%d_%H-%M-%S")

        # Define a base filename with the formatted date
        file_name = f"{formatted_date}.pcapng"

        # Write the packets to the file
        print(f"Saving captured packets to '{file_name}'")
        try:
            wrpcapng(file_name, packets)
        except Exception as e:
            print(f"Unable to save packets to capture file '{file_name}': {e}")

    # Construct the dataframe from packets
    df = construct_dataframe_from_capture(
        packets, mac_address_to_interface_mapping=mac_addresses_mapping_dict
    )

    # Create and display the diagram
    create_and_display_sankey_diagram(df)

    # try_sunburst(df, metric="frames")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

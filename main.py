import logging
import sys

# Do this to suppress warnings when loading scapy module
import scapy.packet

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import get_if_addr, get_if_list, get_if_hwaddr, sniff
import plotly.graph_objects as go
import pandas as pd
from scapy.all import rdpcap
from enum import Enum
from typing import Union
from itertools import pairwise
from tqdm import tqdm

MacAddress = str
IPv4Address = str
IPv6Address = str
IpAddress = Union[IPv4Address, IPv6Address]
Interface = str
Length = int

IpAddressInterfaceDict = dict[IpAddress, Interface]
my_ip_addresses: IpAddressInterfaceDict = dict()
MacAddressInterfaceDict = dict[MacAddress, Interface]
my_mac_addresses: MacAddressInterfaceDict = dict()


class Scope(Enum):
    BROADCAST = "broadcast"
    MULTICAST = "multicast"
    UNICAST = "unicast"


ethernet_type_to_protocol = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x9104: "Eero",
    # Add more types as needed
}


class Direction(Enum):
    TRANSMIT = "transmit"
    RECEIVE = "receive"


def check_frame_scope(frame: scapy.packet.Packet) -> Enum:
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


def check_frame_direction(
    frame: scapy.packet.Packet, my_mac_addresses: MacAddressInterfaceDict
) -> Enum:
    if frame.src in my_mac_addresses:
        return Direction.TRANSMIT
    return Direction.RECEIVE


def packet_callback(packet):
    scope = check_frame_scope(packet)
    direction = check_frame_direction(packet, my_mac_addresses)
    # print(packet.summary())
    print(f"{direction.value} {scope.value=}")
    # if scope == Scope.MULTICAST and direction == Direction.TRANSMIT:
    #     print("!" * 80)


def list_mac_addresses() -> list:
    mac_addresses = []
    for interface in get_if_list():
        try:
            mac_address = get_if_hwaddr(interface)
            # Filtering out interfaces that might not have a MAC address
            if mac_address != "00:00:00:00:00:00":
                mac_addresses.append((interface, mac_address))
        except ValueError:
            # This handles cases where an interface might not have a MAC address
            pass
    return mac_addresses


def list_ip_addresses() -> list:
    ip_addresses = []
    for interface in get_if_list():
        try:
            ip_address = get_if_addr(interface)
            # Filtering out interfaces that might not have an IP address assigned
            if ip_address != "0.0.0.0":
                ip_addresses.append((interface, ip_address))
        except ValueError:
            # This handles cases where an interface might not have an IP address
            pass
    return ip_addresses


# def edges_from_unique_paths(df: pd.DataFrame) -> pd.DataFrame:
#     """Generate a "long" set of edges, from a "wide" set of unique paths.
#
#     Ignores any edges starting with an underscore.
#
#     Args:
#         df: DataFrame with n-1 columns that represent "levels",
#             followed by a single numeric count/weight column.
#
#     Returns:
#         A DataFrame with three columns: (source, target, weight)
#
#     """
#
#     from collections import defaultdict
#
#     edges = defaultdict(int)
#
#     for idx, x in df.iterrows():
#         only_visible = x.loc[lambda x: x.str.startswith("_") != True]
#         n = only_visible["n"]
#         paths = only_visible.drop("n")
#         for a, b in zip(paths[:-1], paths[1:]):
#             edges[(a, b)] += n
#
#     return pd.DataFrame(
#         [(a, b, n) for (a, b), n in edges.items()],
#         columns=["source", "target", "count"],
#     )
#
#
# def make_sankey_params_v1(df: pd.DataFrame) -> dict:
#     """Generate parameter dicts for go.Figure plotting function"""
#
#     # Unpack columns into lists
#     sources, targets, values = df.values.T.tolist()
#
#     # Create list of unique labels across node columns (source, target)
#     labels = list(df["source"].pipe(set) | df["target"].pipe(set))
#
#     # Map actual labels to their index value
#     source_idx = list(map(labels.index, sources))
#     target_idx = list(map(labels.index, targets))
#
#     # Assemble final outputs into expected format
#     nodes_dict = {"label": labels}
#     links_dict = {"source": source_idx, "target": target_idx, "value": values}
#
#     return nodes_dict, links_dict
#


def try_sankey(df, metric=None):

    # I'd really like to be able to trace a flow from beginning to end
    #  ex: https://public.tableau.com/app/profile/actinvision/viz/SuperstoreSankeyShowcaseLOD/Sankey

    # data for which fields to use for the "path" when showing receive/transmit
    dir_path = {
        "receive": [
            "l4_source",
            "l3_type",
            "l3_source",
            "type",
            "source_mac",
            "destination_mac",
        ],
        "transmit": [
            "source_mac",
            "destination_mac",
            "type",
            "l3_destination",
            "l3_type",
            "l4_destination",
        ],
    }
    # The idea here is to do a groupby for each pair of columns from the "path" in order to create the
    # count for them (eg frames or bytes)
    for direction, path in dir_path.items():
        # Create the pairs from the list
        # eg [ A, B, C, D] -> (A,B ), (B,C), (C,D)
        path_pairs = list(pairwise(path))
        # print(f"{direction}, {path_pairs=}")
        # Map each unique value of interesting fields to an index number to give to sankey
        all_nodes = pd.concat([df[column_name] for column_name in path]).unique()
        node_indices = {node: index for index, node in enumerate(all_nodes)}

        # print(f"{node_indices=}")
        combined_df = pd.DataFrame()

        for source, target in path_pairs:
            # print(f"{source=}, {target=}, {metric=}")

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

            # print(agg_data)
            # Accumulate the dataframe
            combined_df = pd.concat([combined_df, agg_data])

        # Creating the Sankey diagram
        # Hardcoding alignment based on receive/transmit to make nodes with no outflow (eg ARP) position
        # properly.   There is probably a better way to do this
        if direction == "receive":
            alignment = "right"
        else:
            alignment = "left"

        fig = go.Figure(
            data=[
                go.Sankey(
                    node=dict(
                        pad=15,
                        thickness=20,
                        line=dict(color="black", width=0.5),
                        label=list(all_nodes),
                        align=alignment
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

        fig.update_layout(title_text=f"Network {metric} {direction}", font_size=10)
        fig.show()

        input(f"That was {direction}")



def try_sunburst(df, metric=None):
    paths = ["destination_mac", "source_mac"]

    res = list(pairwise(paths))
    for source, target in res:
        receive_data = (
            df.groupby(
                [source, target],
                dropna=False,
            )[metric]
            .sum()
            .reset_index()
        )
        print(receive_data)
    # receive_data = (
    #     df.query('direction == "receive"')
    #     .groupby(
    #         [
    #             # "direction",
    #             "source_mac",
    #             "destination_mac",
    #             "type",
    #             # "scope",
    #             "l3_source",
    #             "l3_type",
    #             "l4_source",
    #         ],
    #         dropna=False,
    #     )["frames"]
    #     .sum()
    #     .reset_index()
    # )
    # transmit_data = (
    #     df.query('direction == "transmit"')
    #     .groupby(
    #         [
    #             # "direction",
    #             "source_mac",
    #             "destination_mac",
    #             "type",
    #             # "scope",
    #             "l3_destination",
    #             "l3_type",
    #             "l4_destination",
    #         ],
    #         dropna=False,
    #     )["frames"]
    #     .sum()
    #     .reset_index()
    # )
    #
    # fig = px.sunburst(
    #     receive_data,
    #     path=[
    #         "destination_mac",
    #         "source_mac",
    #         "type",
    #         "l3_source",
    #         "l3_type",
    #         "l4_source",
    #     ],
    #     values="frames",
    #     color="destination_mac",
    # )
    # fig = px.sunburst(
    #     transmit_data,
    #     path=[
    #         "source_mac",
    #         "destination_mac",
    #         "type",
    #         "l3_destination",
    #         "l3_type",
    #         "l4_destination",
    #     ],
    #     values="frames",
    #     color="source_mac",
    # )
    # fig = make_subplots(rows=1, cols=2)
    # fig.add_trace([sunburst_1], row=1, col=1)
    #
    # fig.add_trace([sunburst_2], row=1, col=2)

    # fig.show()


def construct_dataframe_from_capture(packets: scapy.all.PacketList) -> pd.DataFrame:
    # Layer 2
    data = []
    " "

    for packet in packets:
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
            "direction": f"{check_frame_direction(packet, my_mac_addresses).value}",
            "scope": f"{check_frame_scope(packet).value}",
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

    # print(df)
    return df


def main():
    def custom_action(packet):
        # This is the callback function executed for each packet captured
        # Update the tqdm progress bar by 1 for each packet
        pbar.update(1)
        # You can add more packet processing logic here

    # List all IP addresses
    ip_addresses = list_ip_addresses()
    for interface, ip in ip_addresses:
        print(f"Interface: {interface}, IP Address: {ip}")
        my_ip_addresses[ip] = interface

    mac_addresses = list_mac_addresses()
    for interface, mac in mac_addresses:
        print(f"Interface: {interface}, MAC Address: {mac}")
        my_mac_addresses[mac] = interface

    # Load packet capture or sniff traffic
    packet_capture_file = None
    # packet_capture_file = "blop.pcapng"

    if packet_capture_file:
        packets = rdpcap(packet_capture_file)
    else:
        # Initialize a tqdm progress bar
        packet_count = 10_000
        with tqdm(desc='Packets Captured', unit=' packets', total=packet_count) as pbar:

            packets = sniff(
                iface="en0",
                prn=custom_action,
                count=packet_count
                # stop_filter=lambda x: pbar.n >= packet_count
            )

    df = construct_dataframe_from_capture(packets)
    try_sankey(df, metric="length")
    # try_sunburst(df, metric="frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())

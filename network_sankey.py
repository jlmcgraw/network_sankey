#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# "anywidget",
# "dash",
# "pandas",
# "plotly",
# "ruff",
# "scapy",
# "tqdm",
# ]
# ///


import argparse
import hashlib
import logging
import sys
from enum import Enum
from itertools import pairwise

import dash
import pandas as pd
import plotly.graph_objects as go
import scapy.packet
from dash import Dash, Input, Output, State, dcc, html
from plotly.graph_objects import FigureWidget
from scapy.all import get_if_addr, get_if_hwaddr, get_if_list, rdpcap, sniff

from models import Direction, IpAddressInterfaceDict, MacAddressInterfaceDict, Scope, ethernet_type_to_protocol_lookup

# Do this to suppress warnings when loading scapy module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Maintain a stable mapping from node label to color
NODE_COLOR_MAP: dict[str, str] = {}


def get_color_for_label(label: str) -> str:
    """Return a consistent hex color for the given label."""
    if label not in NODE_COLOR_MAP:
        digest = hashlib.sha256(label.encode()).hexdigest()[:6]
        NODE_COLOR_MAP[label] = f"#{digest}"
    return NODE_COLOR_MAP[label]


def determine_frame_scope(frame: scapy.packet.Packet) -> Enum:
    """Determine whether frame is broadcast, multicast, or unicast
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


def determine_frame_direction(frame: scapy.packet.Packet, my_mac_addresses: MacAddressInterfaceDict) -> Enum:
    if frame.src in my_mac_addresses:
        return Direction.TRANSMIT
    return Direction.RECEIVE


def create_mac_to_interface_mapping() -> MacAddressInterfaceDict:
    """Create a mac->interface mapping dict
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
    """Create an ip->interface mapping dict
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


def compute_sankey_data(
    df: pd.DataFrame, direction: str, metric: str, interface_label: str = "interface",
) -> tuple[list[str], list[int], list[int], list[int], list[float] | None]:
    """Return labels, links and optional x positions for a Sankey diagram."""
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
            "alignment": "left",
        },
    }

    if direction in ("receive", "transmit"):
        values = dir_path[direction]

        if df.empty or not set(values["path"]).issubset(df.columns):
            return [], [], [], [], None

        path_pairs = list(pairwise(values["path"]))
        all_nodes = pd.concat([df[col] for col in values["path"]]).dropna().unique()
        node_indices = {node: idx for idx, node in enumerate(all_nodes)}

        combined_df = pd.DataFrame()
        for source, target in path_pairs:
            agg_data = (
                df.query(f'direction == "{direction}"')
                .groupby([source, target], dropna=False)[metric]
                .sum()
                .reset_index()
            )
            agg_data = agg_data.dropna(subset=[source, target])
            agg_data["SourceID"] = agg_data[source].apply(lambda x: node_indices[x] if pd.notnull(x) else x)
            agg_data["TargetID"] = agg_data[target].apply(lambda x: node_indices[x] if pd.notnull(x) else x)
            agg_data["Value"] = agg_data[metric]
            combined_df = pd.concat([combined_df, agg_data])

        sources = combined_df["SourceID"].tolist()
        targets = combined_df["TargetID"].tolist()
        values_list = combined_df["Value"].tolist()

        return list(all_nodes), sources, targets, values_list, None

    # combined receive and transmit view with interface in the middle
    if df.empty:
        return [], [], [], [], None

    df = df.copy()
    df["interface_label"] = interface_label

    inbound_df = df.query('direction == "receive"').copy()
    outbound_df = df.query('direction == "transmit"').copy()

    def prefix_columns(dir_df: pd.DataFrame, cols: list[str], prefix: str) -> None:
        for col in cols:
            if col in dir_df:
                dir_df[col] = dir_df[col].apply(lambda x: f"{prefix}{x}" if pd.notnull(x) else x)

    prefix_columns(
        inbound_df,
        [
            "l4_source",
            "l3_type",
            "l3_source",
            "type",
            "source_mac",
        ],
        "RX ",
    )

    prefix_columns(
        outbound_df,
        [
            "destination_mac",
            "type",
            "l3_destination",
            "l3_type",
            "l4_destination",
        ],
        "TX ",
    )

    inbound_path = [
        "l4_source",
        "l3_type",
        "l3_source",
        "type",
        "source_mac",
        "interface_label",
    ]
    outbound_path = [
        "interface_label",
        "destination_mac",
        "type",
        "l3_destination",
        "l3_type",
        "l4_destination",
    ]

    if not set(inbound_path + outbound_path).issubset(df.columns):
        return [], [], [], [], None

    def accumulate(dir_df: pd.DataFrame, path: list[str]) -> pd.DataFrame:
        path_pairs = list(pairwise(path))
        combined = pd.DataFrame()
        for source, target in path_pairs:
            agg = dir_df.groupby([source, target], dropna=False)[metric].sum().reset_index()
            agg = agg.dropna(subset=[source, target])
            agg["Source"] = agg[source]
            agg["Target"] = agg[target]
            agg["Value"] = agg[metric]
            combined = pd.concat([combined, agg])
        return combined

    combined_df = pd.concat(
        [accumulate(inbound_df, inbound_path), accumulate(outbound_df, outbound_path)],
        ignore_index=True,
    )

    all_nodes = pd.concat([combined_df["Source"], combined_df["Target"]]).dropna().unique()
    node_indices = {node: idx for idx, node in enumerate(all_nodes)}
    sources = combined_df["Source"].map(node_indices).tolist()
    targets = combined_df["Target"].map(node_indices).tolist()
    values_list = combined_df["Value"].tolist()

    inbound_nodes = pd.concat([inbound_df[col] for col in inbound_path]).dropna().unique().tolist()
    outbound_nodes = pd.concat([outbound_df[col] for col in outbound_path]).dropna().unique().tolist()
    node_x = [0.0] * len(all_nodes)
    for node in outbound_nodes:
        if node in node_indices:
            node_x[node_indices[node]] = 1.0
    for node in inbound_nodes:
        if node in node_indices:
            node_x[node_indices[node]] = 0.0
    if interface_label in node_indices:
        node_x[node_indices[interface_label]] = 0.5

    return list(all_nodes), sources, targets, values_list, node_x


def create_sankey_figure(
    df: pd.DataFrame, direction: str = "transmit", metric: str = "frames", interface_label: str = "interface",
) -> FigureWidget:
    """Create a Sankey figure widget from dataframe."""
    labels, sources, targets, values_list, node_x = compute_sankey_data(df, direction, metric, interface_label)

    fig = FigureWidget(
        data=[
            go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=labels,
                    color=[get_color_for_label(label) for label in labels],
                    **({"x": node_x} if node_x is not None else {}),
                ),
                link=dict(source=sources, target=targets, value=values_list),
            ),
        ],
    )
    fig.update_layout(title_text=f"Network {direction} {metric}", font_size=10)
    return fig


def update_sankey_figure(
    fig: FigureWidget,
    df: pd.DataFrame,
    direction: str = "transmit",
    metric: str = "frames",
    interface_label: str = "interface",
) -> None:
    """Update the given Sankey figure widget using data from ``df``."""
    labels, sources, targets, values_list, node_x = compute_sankey_data(df, direction, metric, interface_label)
    fig.data[0].node.update(
        label=labels,
        color=[get_color_for_label(label) for label in labels],
    )
    if node_x is not None:
        fig.data[0].node.update(x=node_x)
    # update link arrays via the nested link object
    fig.data[0].link.update(source=sources, target=targets, value=values_list)


def create_and_display_sankey_diagram(
    df: pd.DataFrame,
    direction: str = "transmit",
    metric: str = "frames",
    interface_label: str = "interface",
) -> FigureWidget:
    """Return a Sankey diagram as a :class:`FigureWidget`."""
    return create_sankey_figure(df, direction, metric, interface_label)


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
    """Given the captured packets, construct and enrich a dataframe to be used as input for Sankey

    :param packets:
    :param mac_address_to_interface_mapping:
    :return:
    """
    # Layer 2
    data = []

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
        ethernet_frame_type = ethernet_type_to_protocol_lookup.get(ethernet_frame.type, ethernet_frame_type)
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
    """Given the captured packets, construct and enrich a dataframe to be used as input for Sankey

    :param packets:
    :param mac_address_to_interface_mapping:
    :return:
    """
    # Layer 2
    data = []

    for packet in packets:
        # Layer 2
        if not packet.haslayer("Ether"):
            print(f"{packet=}")
            raise ValueError(f"Non-Ethernet frame: {packet}")
        ethernet_frame = packet.getlayer("Ether")
        ethernet_frame_type = f"{ethernet_frame.type:#06x}"
        ethernet_frame_type = ethernet_type_to_protocol_lookup.get(ethernet_frame.type, ethernet_frame_type)
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
    parser = argparse.ArgumentParser(description="A script to capture and display network traffic as a Sankey diagram")
    parser.add_argument(
        "capture_file",
        nargs="?",
        default=None,
        help="Name of capture file to load instead of live traffic",
    )
    parser.add_argument("--batch-size", type=int, default=100, help="Number of packets to capture per batch")
    parser.add_argument(
        "--dash",
        action="store_true",
        help="Use a Dash app to display the live updating diagram",
    )
    parser.add_argument("--interface", type=str, default="en0", help="Interface to use for capture for live traffic")
    parser.add_argument(
        "--direction",
        choices=["transmit", "receive", "both"],
        default="transmit",
        help="Traffic direction to display in the Sankey diagram",
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_command_line_arguments()
    packet_capture_file = args.capture_file
    batch_size = args.batch_size
    capture_interface = args.interface
    use_dash = args.dash
    direction = args.direction

    # List all MAC addresses
    mac_addresses_mapping_dict = create_mac_to_interface_mapping()

    if packet_capture_file:
        print(f"Loading previously captured traffic from '{packet_capture_file}'")
        try:
            packets = rdpcap(packet_capture_file)
        except Exception as e:
            print(f"Unable to load packet capture '{packet_capture_file}': {e}")
            return 1

        df = construct_dataframe_from_capture(packets, mac_address_to_interface_mapping=mac_addresses_mapping_dict)
        fig = create_and_display_sankey_diagram(df, direction=direction, interface_label=capture_interface)
        fig.show()
        return 0

    df = pd.DataFrame()
    fig = create_and_display_sankey_diagram(df, direction=direction, interface_label=capture_interface)

    if use_dash:
        app = Dash(__name__)
        app.layout = html.Div(
            [
                dcc.Graph(id="graph", figure=fig),
                html.Button("Pause", id="pause-button", n_clicks=0),
                html.Button("Clear", id="clear-button", n_clicks=0),
                dcc.Interval(id="interval", interval=3000, n_intervals=0),
                dcc.Store(id="paused", data=False),
            ],
        )

        @app.callback(
            Output("pause-button", "children"),
            Output("paused", "data"),
            Input("pause-button", "n_clicks"),
            State("paused", "data"),
        )
        def toggle_pause(n_clicks, paused):
            if n_clicks is None or n_clicks == 0:
                return "Pause", paused
            paused = not paused
            return ("Unpause" if paused else "Pause"), paused

        @app.callback(
            Output("graph", "figure"),
            Input("interval", "n_intervals"),
            Input("clear-button", "n_clicks"),
            State("paused", "data"),
        )
        def update_graph(_, clear_clicks, paused):
            nonlocal df
            ctx = dash.callback_context
            if ctx.triggered and ctx.triggered[0]["prop_id"].startswith("clear-button"):
                df = pd.DataFrame()
                update_sankey_figure(fig, df, direction=direction, interface_label=capture_interface)
                return fig
            if paused:
                return fig
            packets = sniff(iface=capture_interface, count=batch_size, timeout=1)
            if packets:
                new_df = construct_dataframe_from_capture(
                    packets,
                    mac_address_to_interface_mapping=mac_addresses_mapping_dict,
                )
                df = pd.concat([df, new_df], ignore_index=True)
                update_sankey_figure(fig, df, direction=direction, interface_label=capture_interface)
            return fig

        app.run(debug=False)
    else:
        fig.show()
        while True:
            packets = sniff(iface=capture_interface, count=batch_size, timeout=1)
            if not packets:
                continue
            new_df = construct_dataframe_from_capture(
                packets, mac_address_to_interface_mapping=mac_addresses_mapping_dict,
            )
            df = pd.concat([df, new_df], ignore_index=True)
            update_sankey_figure(fig, df, direction=direction, interface_label=capture_interface)

    # try_sunburst(df, metric="frames")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

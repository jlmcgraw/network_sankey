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
    df: pd.DataFrame,
    direction: str,
    metric: str,
    interface_label: str = "interface",
    *,
    sort_nodes: bool = False,
) -> tuple[
    list[str],
    list[int],
    list[int],
    list[int],
    list[float] | None,
    list[float] | None,
]:
    """Return labels, links and optional node positions for a Sankey diagram.

    Parameters
    ----------
    df:
        DataFrame containing captured frame information.
    direction:
        Either ``"transmit"`` or ``"receive"`` or ``"both"``.
    metric:
        Name of the numeric column to aggregate for link weights.
    interface_label:
        Label used for the interface node when ``direction`` is ``"both"``.
    sort_nodes:
        If ``True``, nodes are sorted alphabetically before being displayed.

    Returns
    -------
    labels, sources, targets, values, node_x, node_y
        ``node_x`` and ``node_y`` contain coordinates for the nodes or ``None``
        if the positions are not specified.
    """
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
            return [], [], [], [], None, None

        path_pairs = list(pairwise(values["path"]))
        column_nodes: dict[str, list[str]] = {}
        for col in values["path"]:
            if col not in df:
                continue
            nodes = df[col].dropna().unique()
            column_nodes[col] = sorted(nodes) if sort_nodes else list(nodes)

        all_nodes: list[str] = []
        node_indices: dict[str, int] = {}
        node_y_map: dict[str, float] = {}
        for col, nodes in column_nodes.items():
            step = 1.0 / (len(nodes) + 1)
            for idx, node in enumerate(nodes):
                if node not in node_indices:
                    node_indices[node] = len(all_nodes)
                    all_nodes.append(node)
                node_y_map[node] = step * (idx + 1)

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

        node_y = [node_y_map.get(node, 0.0) for node in all_nodes]

        return list(all_nodes), sources, targets, values_list, None, node_y

    # combined receive and transmit view with interface in the middle
    if df.empty:
        return [], [], [], [], None, None

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
        return [], [], [], [], None, None

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

    column_nodes: list[tuple[str, list[str]]] = []
    for col in inbound_path:
        if col in inbound_df:
            nodes = inbound_df[col].dropna().unique()
            column_nodes.append((col, sorted(nodes) if sort_nodes else list(nodes)))
    for col in outbound_path:
        if col in outbound_df:
            nodes = outbound_df[col].dropna().unique()
            column_nodes.append((col, sorted(nodes) if sort_nodes else list(nodes)))

    all_nodes: list[str] = []
    node_indices: dict[str, int] = {}
    node_y_map: dict[str, float] = {}
    for _col, nodes in column_nodes:
        step = 1.0 / (len(nodes) + 1)
        for idx, node in enumerate(nodes):
            if node not in node_indices:
                node_indices[node] = len(all_nodes)
                all_nodes.append(node)
            node_y_map[node] = step * (idx + 1)

    sources = combined_df["Source"].map(node_indices).tolist()
    targets = combined_df["Target"].map(node_indices).tolist()
    values_list = combined_df["Value"].tolist()

    inbound_column_x = {
        "l4_source": 0.0,
        "l3_type": 0.2,
        "l3_source": 0.2,
        "type": 0.4,
        "source_mac": 0.4,
        "interface_label": 0.5,
    }
    outbound_column_x = {
        "interface_label": 0.5,
        "destination_mac": 0.6,
        "type": 0.6,
        "l3_destination": 0.8,
        "l3_type": 0.8,
        "l4_destination": 1.0,
    }

    node_x_map: dict[str, float] = {}
    for col, x in inbound_column_x.items():
        if col in inbound_df:
            for val in inbound_df[col].dropna().unique():
                node_x_map[val] = x
    for col, x in outbound_column_x.items():
        if col in outbound_df:
            for val in outbound_df[col].dropna().unique():
                node_x_map[val] = x

    node_x = [node_x_map.get(node, 0.0) for node in all_nodes]
    node_y = [node_y_map.get(node, 0.0) for node in all_nodes]

    return list(all_nodes), sources, targets, values_list, node_x, node_y


def create_sankey_figure(
    df: pd.DataFrame,
    direction: str = "transmit",
    metric: str = "frames",
    interface_label: str = "interface",
    *,
    sort_nodes: bool = False,
) -> FigureWidget:
    """Create a Sankey figure widget from dataframe."""
    labels, sources, targets, values_list, node_x, node_y = compute_sankey_data(
        df,
        direction,
        metric,
        interface_label,
        sort_nodes=sort_nodes,
    )

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
                    **({"y": node_y} if node_y is not None else {}),
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
    *,
    sort_nodes: bool = False,
) -> None:
    """Update the given Sankey figure widget using data from ``df``."""
    labels, sources, targets, values_list, node_x, node_y = compute_sankey_data(
        df,
        direction,
        metric,
        interface_label,
        sort_nodes=sort_nodes,
    )
    fig.data[0].node.update(
        label=labels,
        color=[get_color_for_label(label) for label in labels],
    )
    if node_x is not None:
        fig.data[0].node.update(x=node_x)
    if node_y is not None:
        fig.data[0].node.update(y=node_y)
    # update link arrays via the nested link object
    fig.data[0].link.update(source=sources, target=targets, value=values_list)


def create_and_display_sankey_diagram(
    df: pd.DataFrame,
    direction: str = "transmit",
    metric: str = "frames",
    interface_label: str = "interface",
    *,
    sort_nodes: bool = False,
) -> FigureWidget:
    """Return a Sankey diagram as a :class:`FigureWidget`."""
    return create_sankey_figure(
        df,
        direction,
        metric,
        interface_label,
        sort_nodes=sort_nodes,
    )


def compute_counts(df: pd.DataFrame, metric: str) -> tuple[int, int]:
    """Return total inbound and outbound traffic counts.

    Parameters
    ----------
    df:
        DataFrame holding captured packets.
    metric:
        Metric column to aggregate. Typically ``"frames"`` or ``"length"``.
    """
    if df.empty or "direction" not in df or metric not in df:
        return 0, 0
    total_in = int(df[df["direction"] == "receive"][metric].sum())
    total_out = int(df[df["direction"] == "transmit"][metric].sum())
    return total_in, total_out


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
    parser.add_argument(
        "--sort-nodes",
        action="store_true",
        help="Sort nodes alphabetically by their label",
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
    sort_nodes = args.sort_nodes

    # List all MAC addresses
    mac_addresses_mapping_dict = create_mac_to_interface_mapping()

    if packet_capture_file:
        print(f"Loading previously captured traffic from '{packet_capture_file}'")
        try:
            packets = rdpcap(packet_capture_file)
        except Exception as e:
            print(f"Unable to load packet capture '{packet_capture_file}': {e}")
            return 1

        df = construct_dataframe_from_capture(
            packets,
            mac_address_to_interface_mapping=mac_addresses_mapping_dict,
        )
        fig = create_and_display_sankey_diagram(
            df,
            direction=direction,
            interface_label=capture_interface,
            sort_nodes=sort_nodes,
        )
        fig.show()
        return 0

    df = pd.DataFrame()
    fig = create_and_display_sankey_diagram(
        df,
        direction=direction,
        metric="frames",
        interface_label=capture_interface,
        sort_nodes=sort_nodes,
    )

    if use_dash:
        app = Dash(__name__)
        app.layout = html.Div(
            [
                dcc.Graph(id="graph", figure=fig),
                html.Div(id="counts-div"),
                html.Button("Pause", id="pause-button", n_clicks=0),
                html.Button("Clear", id="clear-button", n_clicks=0),
                html.Button("Show Bytes", id="metric-toggle-button", n_clicks=0),
                dcc.Interval(id="interval", interval=3000, n_intervals=0),
                dcc.Store(id="paused", data=False),
                dcc.Store(id="metric", data="frames"),
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
            Output("metric-toggle-button", "children"),
            Output("metric", "data"),
            Input("metric-toggle-button", "n_clicks"),
            State("metric", "data"),
        )
        def toggle_metric(n_clicks, metric):
            if n_clicks is None or n_clicks == 0:
                label = "Show Bytes" if metric == "frames" else "Show Frames"
                return label, metric
            metric = "length" if metric == "frames" else "frames"
            label = "Show Bytes" if metric == "frames" else "Show Frames"
            return label, metric

        @app.callback(
            Output("graph", "figure"),
            Output("counts-div", "children"),
            Input("interval", "n_intervals"),
            Input("clear-button", "n_clicks"),
            Input("metric", "data"),
            State("paused", "data"),
        )
        def update_graph(n_intervals, clear_clicks, metric, paused):
            nonlocal df
            triggered = dash.callback_context.triggered_id
            if triggered == "clear-button":
                df = pd.DataFrame()
                update_sankey_figure(
                    fig,
                    df,
                    direction=direction,
                    metric=metric,
                    interface_label=capture_interface,
                    sort_nodes=sort_nodes,
                )
                counts = "RX 0 {unit} | TX 0 {unit}".format(
                    unit="bytes" if metric == "length" else "frames",
                )
                return fig, counts
            if paused:
                total_in, total_out = compute_counts(df, metric)
                counts = (
                    f"RX {total_in} {'bytes' if metric == 'length' else 'frames'} | "
                    f"TX {total_out} {'bytes' if metric == 'length' else 'frames'}"
                )
                return fig, counts
            packets = sniff(iface=capture_interface, count=batch_size, timeout=1)
            if packets:
                new_df = construct_dataframe_from_capture(
                    packets,
                    mac_address_to_interface_mapping=mac_addresses_mapping_dict,
                )
                df = pd.concat([df, new_df], ignore_index=True)
                update_sankey_figure(
                    fig,
                    df,
                    direction=direction,
                    metric=metric,
                    interface_label=capture_interface,
                    sort_nodes=sort_nodes,
                )
            total_in, total_out = compute_counts(df, metric)
            counts = (
                f"RX {total_in} {'bytes' if metric == 'length' else 'frames'} | "
                f"TX {total_out} {'bytes' if metric == 'length' else 'frames'}"
            )
            return fig, counts

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
            update_sankey_figure(
                fig,
                df,
                direction=direction,
                metric="frames",
                interface_label=capture_interface,
                sort_nodes=sort_nodes,
            )
            total_in, total_out = compute_counts(df, "frames")
            print(f"RX {total_in} frames | TX {total_out} frames")

    # try_sunburst(df, metric="frames")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

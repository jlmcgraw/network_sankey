#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# "anywidget",
# "dash",
# "pandas",
# "plotly",
# "scapy",
# "tqdm",
# ]
# ///
"""Utilities for building network traffic Sankey diagrams."""
import argparse
import hashlib
import ipaddress
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


def _safe_direction_sum(df: pd.DataFrame, direction: str, metric: str) -> int:
    """Return the sum for ``metric`` filtering by ``direction`` if columns exist."""
    if "direction" not in df or metric not in df:
        return 0
    return int(df.loc[df["direction"] == direction, metric].sum())


def get_color_for_label(label: str | int) -> str:
    """Return a consistent hex color for the given label."""
    label = str(label)
    if label not in NODE_COLOR_MAP:
        digest = hashlib.sha256(label.encode()).hexdigest()[:6]
        NODE_COLOR_MAP[label] = f"#{digest}"
    return NODE_COLOR_MAP[label]


def determine_frame_scope(frame: scapy.packet.Packet) -> Enum:
    """Return the scope of ``frame`` as broadcast, multicast, or unicast."""
    if not frame.haslayer("Ether"):
        logging.debug("Unexpected frame without Ethernet layer: %s", frame)
        raise ValueError("Non-Ethernet frame")

    dst_mac = frame.dst
    if dst_mac == "ff:ff:ff:ff:ff:ff":
        return Scope.BROADCAST
    elif int(dst_mac.split(":")[0], 16) & 1:
        return Scope.MULTICAST

    return Scope.UNICAST


def determine_frame_direction(
    frame: scapy.packet.Packet,
    my_mac_addresses: MacAddressInterfaceDict,
) -> Enum:
    """Return :class:`Direction` of ``frame`` relative to ``my_mac_addresses``."""
    if frame.src in my_mac_addresses:
        return Direction.TRANSMIT
    return Direction.RECEIVE


def create_mac_to_interface_mapping() -> MacAddressInterfaceDict:
    """Return a mapping of MAC address to interface name."""
    mac_addresses_mapping_dict: MacAddressInterfaceDict = {}

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
    """Return a mapping of IP address to interface name."""
    ip_to_interface_dict: IpAddressInterfaceDict = {}

    for interface in get_if_list():
        try:
            ip_address = get_if_addr(interface)
            # Filtering out interfaces that might not have an IP address assigned
            if ip_address != "0.0.0.0":  # noqa: S104
                ip_to_interface_dict[ip_address] = interface
        except ValueError:
            # This handles cases where an interface might not have an IP address
            pass

    return ip_to_interface_dict


DIRECTION_PATHS: dict[str, list[str]] = {
    "receive": [
        "l4_source",
        "l3_type",
        "l3_source",
        "l3_source_scope",
        "l2_type",
        "source_mac",
        "scope",
        "destination_mac",
    ],
    "transmit": [
        "source_mac",
        "scope",
        "destination_mac",
        "l2_type",
        "l3_destination_scope",
        "l3_destination",
        "l3_type",
        "l4_destination",
    ],
}

DIRECTION_COLUMN_X: dict[str, dict[str, float]] = {
    "receive": {
        "l4_source": 0.0,
        "l3_type": 0.2,
        "l3_source": 0.4,
        "l2_type": 0.5,
        "source_mac": 0.7,
        "destination_mac": 1.0,
    },
    "transmit": {
        "source_mac": 0.0,
        "destination_mac": 0.3,
        "l2_type": 0.5,
        "l3_destination": 0.7,
        "l3_type": 0.8,
        "l4_destination": 1.0,
    },
}

INBOUND_PATH = [
    "l4_source",
    "l3_type",
    "l3_source",
    "l2_type",
    "source_mac",
    "scope",
    "interface_label",
]

OUTBOUND_PATH = [
    "interface_label",
    "scope",
    "destination_mac",
    "l2_type",
    "l3_destination",
    "l3_type",
    "l4_destination",
]

INBOUND_COLUMN_X = {
    "l4_source": 0.0,
    "l3_type": 0.2,
    "l3_source": 0.2,
    "l2_type": 0.3,
    "source_mac": 0.4,
    "interface_label": 0.5,
}

OUTBOUND_COLUMN_X = {
    "interface_label": 0.5,
    "destination_mac": 0.6,
    "l2_type": 0.7,
    "l3_destination": 0.8,
    "l3_type": 0.8,
    "l4_destination": 1.0,
}


def prefix_columns(df: pd.DataFrame, columns: list[str], prefix: str) -> None:
    """Apply ``prefix`` to ``columns`` in ``df`` if present."""
    for column in columns:
        if column in df:
            df[column] = df[column].apply(lambda x: f"{prefix}{x}" if pd.notnull(x) else x)


def _aggregate_links(df: pd.DataFrame, path: list[str], metric: str) -> pd.DataFrame:
    """Aggregate ``metric`` for each consecutive pair of columns in ``path``."""
    links = pd.DataFrame()
    for source, target in pairwise(path):
        agg = df.groupby([source, target], dropna=False)[metric].sum().reset_index()
        agg = agg.dropna(subset=[source, target])
        agg["Source"] = agg[source]
        agg["Target"] = agg[target]
        agg["Value"] = agg[metric]
        links = pd.concat([links, agg])
    return links


def _compute_directional_sankey_data(
    df: pd.DataFrame, direction: str, metric: str,
) -> tuple[list[str], list[int], list[int], list[int], list[float]]:
    path = DIRECTION_PATHS[direction]

    if df.empty or not set(path).issubset(df.columns):
        return [], [], [], [], None

    filtered = df.query(f'direction == "{direction}"')
    combined_df = _aggregate_links(filtered, path, metric)

    combined_df["Source"] = combined_df["Source"].astype(str)
    combined_df["Target"] = combined_df["Target"].astype(str)

    all_nodes = pd.concat([combined_df["Source"], combined_df["Target"]]).dropna().unique()
    node_indices = {node: idx for idx, node in enumerate(all_nodes)}
    sources = combined_df["Source"].map(node_indices).tolist()
    targets = combined_df["Target"].map(node_indices).tolist()
    values_list = combined_df["Value"].tolist()

    node_x_map: dict[str, float] = {}
    col_map = DIRECTION_COLUMN_X.get(direction, {})
    for col in path:
        if col in filtered:
            values = filtered[col].dropna().unique()
            for val in values:
                node_x_map.setdefault(str(val), col_map.get(col, 0.0))

    node_x = [node_x_map.get(node, 0.0) for node in all_nodes]

    return list(all_nodes), sources, targets, values_list, node_x


def _compute_combined_sankey_data(
    df: pd.DataFrame, metric: str, interface_label: str,
) -> tuple[list[str], list[int], list[int], list[int], list[float]]:
    if df.empty:
        return [], [], [], [], None

    df = df.copy()
    df["interface_label"] = interface_label

    inbound_df = df.query('direction == "receive"').copy()
    outbound_df = df.query('direction == "transmit"').copy()

    prefix_columns(inbound_df, INBOUND_PATH[:-1], "RX ")
    prefix_columns(outbound_df, OUTBOUND_PATH[1:], "TX ")

    if not set(INBOUND_PATH + OUTBOUND_PATH).issubset(df.columns):
        return [], [], [], [], None

    combined_df = pd.concat(
        [
            _aggregate_links(inbound_df, INBOUND_PATH, metric),
            _aggregate_links(outbound_df, OUTBOUND_PATH, metric),
        ],
        ignore_index=True,
    )

    combined_df["Source"] = combined_df["Source"].astype(str)
    combined_df["Target"] = combined_df["Target"].astype(str)

    all_nodes = pd.concat([combined_df["Source"], combined_df["Target"]]).dropna().unique()
    node_indices = {node: idx for idx, node in enumerate(all_nodes)}
    sources = combined_df["Source"].map(node_indices).tolist()
    targets = combined_df["Target"].map(node_indices).tolist()
    values_list = combined_df["Value"].tolist()

    node_x_map: dict[str, float] = {}
    for col in INBOUND_PATH:
        if col in inbound_df:
            values = inbound_df[col].dropna().unique()
            for val in values:
                node_x_map.setdefault(str(val), INBOUND_COLUMN_X.get(col, 0.0))
    for col in OUTBOUND_PATH:
        if col in outbound_df:
            values = outbound_df[col].dropna().unique()
            for val in values:
                node_x_map.setdefault(str(val), OUTBOUND_COLUMN_X.get(col, 0.0))

    node_x = [node_x_map.get(node, 0.0) for node in all_nodes]

    return list(all_nodes), sources, targets, values_list, node_x


def compute_sankey_data(
    df: pd.DataFrame,
    direction: str,
    metric: str,
    interface_label: str = "interface",
) -> tuple[list[str], list[int], list[int], list[int], list[float] | None]:
    """Return labels, links and optional x positions for a Sankey diagram."""
    if direction in ("receive", "transmit"):
        return _compute_directional_sankey_data(df, direction, metric)

    return _compute_combined_sankey_data(df, metric, interface_label)


def create_sankey_figure(
    df: pd.DataFrame,
    direction: str = "transmit",
    metric: str = "frames",
    interface_label: str = "interface",
) -> FigureWidget:
    """Create a Sankey figure widget from dataframe."""
    labels, sources, targets, values_list, node_x = compute_sankey_data(df, direction, metric, interface_label)

    fig = FigureWidget(
        data=[
            go.Sankey(
                arrangement="fixed",
                node=dict(
                    pad=15,
                    thickness=20,
                    line={"color": "black", "width": 0.5},
                    label=labels,
                    color=[get_color_for_label(label) for label in labels],
                    **({"x": node_x} if node_x is not None else {}),
                ),
                link={"source": sources, "target": targets, "value": values_list},
            ),
        ],
    )
    fig.update_layout(title_text=f"Network Traffic: {direction} {metric}", font_size=10)
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
    fig.data[0].arrangement = "fixed"
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



def get_ip_scope(ip_address_str: str) -> str:
    """Return the general address scope for ``ip_address_str``."""
    # IPv4 scopes
    # Public (Global)
    # Private (Local)
    # Link-local
    # Multicast
    # Documentation
    # Reserved blocks
    try:
        ip_obj = ipaddress.ip_address(ip_address_str)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj.is_link_local:
                return "Link-Local"
            elif ip_obj.is_private:
                return "Private"
            elif ip_obj.is_loopback:
                return "Loopback"
            elif ip_obj.is_multicast:
                return "Multicast"
            elif ip_obj.is_reserved:
                return "Reserved"
            elif ip_obj.is_unspecified:
                return "Unspecified"
            elif ip_obj.is_global:
                return "Global"
            else:
                return "Not categorized"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.is_link_local:
                return "Link-Local"
            elif ip_obj.is_site_local:
                return "Site Local"
            elif ip_obj.is_private:
                return "Private"
            elif ip_obj.is_loopback:
                return "Loopback"
            elif ip_obj.is_multicast:
                return "Multicast"
            elif ip_obj.is_reserved:
                return "Reserved"
            elif ip_obj.is_unspecified:
                return "Unspecified"
            elif ip_obj.is_global:
                return "Global"
            else:
                return "Not categorized"
        else:
            return "Neither IPv4 or IPv6"
    except ipaddress.AddressValueError:
        return "Invalid IP Address"

def construct_dataframe_from_capture(
    packets: scapy.all.PacketList,
    mac_address_to_interface_mapping: MacAddressInterfaceDict,
) -> pd.DataFrame:
    """Given captured packets, enrich and return a dataframe for Sankey diagrams.

    :param packets:
    :param mac_address_to_interface_mapping:
    :return:
    """
    # Layer 2
    data = []

    for packet in packets:
        l3_source = None
        l3_source_scope = None
        l3_destination = None
        l3_destination_scope = None
        l3_type = None
        l4_source = None
        l4_destination = None
        # scapy.layers.inet.TCP
        # 'scapy.layers.inet6.
        # Extracting Layer 2 (Ethernet frame) information
        # print(packet.layers())

        # Layer 2
        if not packet.haslayer("Ether"):
            logging.debug("Non-Ethernet packet: %s", packet)
            raise ValueError(f"Non-Ethernet frame: {packet}")
        ethernet_frame = packet.getlayer("Ether")
        ethernet_frame_type = f"{ethernet_frame.type:#06x}"
        ethernet_frame_type = ethernet_type_to_protocol_lookup.get(ethernet_frame.type, ethernet_frame_type)
        # print(f"{ethernet_frame_type=}")
        # Layer 3
        if packet.haslayer("IP"):
            l3_source = packet["IP"].src
            l3_source_scope = get_ip_scope(l3_source)
            l3_destination = packet["IP"].dst
            l3_destination_scope = get_ip_scope(l3_destination)
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
            l3_source_scope = get_ip_scope(l3_source)
            l3_destination = packet["IPv6"].dst
            l3_destination_scope = get_ip_scope(l3_destination)
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
            "l2_type": ethernet_frame_type,
            "length": len(packet),
            # "interface": {my}
            "direction": f"{determine_frame_direction(packet, mac_address_to_interface_mapping).value}",
            "scope": f"{determine_frame_scope(packet).value}",
            "frames": 1,
            "l3_source": l3_source,
            "l3_source_scope": l3_source_scope,
            "l3_destination": l3_destination,
            "l3_destination_scope": l3_destination_scope,
            "l3_type": l3_type,
            "l4_source": l4_source,
            "l4_destination": l4_destination,
        }

        data.append(packet_data)

    df = pd.DataFrame(data)
    # df.fillna(value=np.nan, inplace=True)
    # When these columns contain a NaN value (eg ARP), the rest of the values get converted to floats (eg 53 -> 53.0)
    # Convert the column types to Int64, which supports a nullable value, to avoid this
    df["l4_source"] = df["l4_source"].astype("Int64")
    df["l4_destination"] = df["l4_destination"].astype("Int64")
    return df


def parse_command_line_arguments() -> argparse.Namespace:
    """Parse and return command-line arguments."""
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


def main() -> int:
    """Entry point for the command-line interface."""
    args = parse_command_line_arguments()
    packet_capture_file = args.capture_file
    batch_size = args.batch_size
    capture_interface = args.interface
    use_dash = args.dash
    direction = args.direction

    # List all MAC addresses
    mac_addresses_mapping_dict = create_mac_to_interface_mapping()

    if packet_capture_file:
        logging.info("Loading previously captured traffic from '%s'", packet_capture_file)
        try:
            packets = rdpcap(packet_capture_file)
        except Exception as e:
            logging.error("Unable to load packet capture '%s': %s", packet_capture_file, e)
            return 1

        df = construct_dataframe_from_capture(packets, mac_address_to_interface_mapping=mac_addresses_mapping_dict)
        fig = create_and_display_sankey_diagram(df, direction=direction, interface_label=capture_interface)
        fig.show()
        return 0

    df = pd.DataFrame()
    fig = create_and_display_sankey_diagram(
        df,
        direction=direction,
        metric="frames",
        interface_label=capture_interface,
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
        def toggle_pause(n_clicks: int | None, paused: bool) -> tuple[str, bool]:
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
        def toggle_metric(n_clicks: int | None, metric: str) -> tuple[str, str]:
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
        def update_graph(
            _n_intervals: int,
            _clear_clicks: int | None,
            metric: str,
            paused: bool,
        ) -> tuple[FigureWidget, str]:
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
                )
                counts = "RX 0 {unit} | TX 0 {unit}".format(unit="bytes" if metric == "length" else "frames")
                return fig, counts
            if paused:
                total_in = _safe_direction_sum(df, "receive", metric)
                total_out = _safe_direction_sum(df, "transmit", metric)
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
                )
            total_in = _safe_direction_sum(df, "receive", metric)
            total_out = _safe_direction_sum(df, "transmit", metric)
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
                packets,
                mac_address_to_interface_mapping=mac_addresses_mapping_dict,
            )
            df = pd.concat([df, new_df], ignore_index=True)
            update_sankey_figure(
                fig,
                df,
                direction=direction,
                metric="frames",
                interface_label=capture_interface,
            )
            total_in = _safe_direction_sum(df, "receive", "frames")
            total_out = _safe_direction_sum(df, "transmit", "frames")
            logging.info("RX %s frames | TX %s frames", total_in, total_out)

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

# Additional tests for network_sankey

from types import ModuleType, SimpleNamespace
import sys

# Stub external dependencies
sys.modules.setdefault(
    "dash",
    SimpleNamespace(Dash=object, Input=object, Output=object, State=object, dcc=SimpleNamespace(), html=SimpleNamespace()),
)
sys.modules.setdefault("dash.dcc", SimpleNamespace())
sys.modules.setdefault("dash.html", SimpleNamespace())

plotly_mod = ModuleType("plotly")
graph_objs = ModuleType("plotly.graph_objects")
graph_objs.FigureWidget = object
graph_objs.Sankey = lambda **kw: SimpleNamespace(node=SimpleNamespace(), link=SimpleNamespace())
sys.modules.setdefault("plotly", plotly_mod)
sys.modules.setdefault("plotly.graph_objects", graph_objs)
scapy_mod = ModuleType("scapy")
packet_mod = ModuleType("scapy.packet")
packet_mod.Packet = object
scapy_mod.packet = packet_mod
all_mod = SimpleNamespace(get_if_list=lambda: [], get_if_hwaddr=lambda iface=None: "", PacketList=list)
scapy_mod.all = all_mod
sys.modules.setdefault("scapy", scapy_mod)
sys.modules.setdefault("scapy.packet", packet_mod)
sys.modules.setdefault("scapy.all", all_mod)

import pandas as pd
import pytest

import network_sankey as ns
from network_sankey import _aggregate_links, compute_sankey_data, parse_command_line_arguments, create_mac_to_interface_mapping, determine_frame_scope


class NoEtherPacket:
    def haslayer(self, layer: str) -> bool:
        return False


def test_determine_frame_scope_no_ether():
    with pytest.raises(ValueError):
        determine_frame_scope(NoEtherPacket())


def test_compute_sankey_data_empty():
    df = pd.DataFrame()
    labels, sources, targets, values, node_x = compute_sankey_data(df, "receive", "frames")
    assert labels == []
    assert sources == targets == values == []
    assert node_x is None


def test_aggregate_links_drops_na():
    df = pd.DataFrame({
        "A": ["a", None, "a"],
        "B": ["b", "c", None],
        "C": ["x", "y", "z"],
        "metric": [1, 2, 3],
    })
    links = _aggregate_links(df, ["A", "B", "C"], "metric")
    assert links[["Source", "Target", "Value"]].to_dict("records") == [
        {"Source": "a", "Target": "b", "Value": 1},
        {"Source": "b", "Target": "x", "Value": 1},
        {"Source": "c", "Target": "y", "Value": 2},
    ]


def test_parse_command_line_arguments_defaults(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog"])
    args = parse_command_line_arguments()
    assert args.capture_file is None
    assert args.batch_size == 100
    assert args.interface == "en0"
    assert args.direction == "transmit"
    assert args.dash is False


def test_create_mac_to_interface_mapping_handles_errors(monkeypatch):
    monkeypatch.setattr(ns, "get_if_list", lambda: ["i1", "i2"])

    def fake_hwaddr(iface):
        if iface == "i1":
            raise ValueError("oops")
        return "00:11:22:33:44:55"

    monkeypatch.setattr(ns, "get_if_hwaddr", fake_hwaddr)
    mapping = create_mac_to_interface_mapping()
    assert mapping == {"00:11:22:33:44:55": "i2"}

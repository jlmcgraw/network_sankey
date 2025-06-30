from pathlib import Path
import sys

# Stub missing external dependencies
from types import ModuleType, SimpleNamespace

sys.modules.setdefault("dash", SimpleNamespace())
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
all_mod = SimpleNamespace(PacketList=list)
scapy_mod.all = all_mod
sys.modules.setdefault("scapy", scapy_mod)
sys.modules.setdefault("scapy.packet", packet_mod)
sys.modules.setdefault("scapy.all", all_mod)

import pandas as pd

import network_sankey_d3 as d3


def test_create_sankey_json():
    df = pd.DataFrame({
        "direction": ["receive"],
        "l4_source": ["a"],
        "l3_type": ["b"],
        "l3_source": ["c"],
        "l3_source_scope": ["s"],
        "l2_type": ["d"],
        "source_mac": ["e"],
        "scope": ["unicast"],
        "destination_mac": ["f"],
        "frames": [1],
    })
    js = d3.create_sankey_json(df, "receive", "frames", "iface")
    assert js["nodes"][0]["name"] == "a"
    assert js["links"][0]["value"] == 1


def test_serve(tmp_path):
    server = d3.serve(tmp_path, 0)
    try:
        host, port = server.server_address
        assert host == "127.0.0.1"
        assert port != 0
    finally:
        server.server_close()

import builtins
from types import SimpleNamespace

import pandas as pd
import pytest

import network_sankey as ns
from network_sankey import (
    _aggregate_links,
    _compute_combined_sankey_data,
    _compute_directional_sankey_data,
    compute_sankey_data,
    create_sankey_figure,
    create_and_display_sankey_diagram,
    determine_frame_direction,
    determine_frame_scope,
    get_color_for_label,
    get_ip_scope,
    prefix_columns,
    update_sankey_figure,
    _safe_direction_sum,
    create_mac_to_interface_mapping,
    create_ip_to_interface_mapping,
    construct_dataframe_from_capture,
)


class FakeLayer:
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)

    def get_field(self, name):
        # return mapping for proto or nh
        return SimpleNamespace(i2s={getattr(self, name): "udp"})


class FakePacket:
    def __init__(self):
        self.time = 123.4
        self.src = "aa:aa:aa:aa:aa:aa"
        self.dst = "bb:bb:bb:bb:bb:bb"
        self.ether = FakeLayer(src=self.src, dst=self.dst, type=0x0800)
        self.ip = FakeLayer(src="192.168.0.1", dst="8.8.8.8", proto=17)
        self.udp = FakeLayer(sport=1234, dport=80)
        self.layers = {"Ether": self.ether, "IP": self.ip, "UDP": self.udp}

    def __len__(self):
        return 60

    def haslayer(self, layer):
        return layer in self.layers

    def getlayer(self, layer):
        return self.layers[layer]

    def __getitem__(self, item):
        return self.layers[item]


@pytest.fixture
def fake_packet():
    return FakePacket()


def test_safe_direction_sum():
    df = pd.DataFrame({"direction": ["receive", "transmit"], "frames": [1, 2]})
    assert ns._safe_direction_sum(df, "receive", "frames") == 1
    assert ns._safe_direction_sum(df, "transmit", "frames") == 2
    # missing columns
    df2 = pd.DataFrame()
    assert ns._safe_direction_sum(df2, "receive", "frames") == 0


def test_color_for_label_stable():
    first = get_color_for_label("a")
    second = get_color_for_label("a")
    assert first == second
    assert first.startswith("#") and len(first) == 7


def test_determine_frame_scope_and_direction(fake_packet):
    mac_map = {"aa:aa:aa:aa:aa:aa": "eth0"}
    assert determine_frame_scope(fake_packet).value == "unicast"
    assert determine_frame_direction(fake_packet, mac_map).value == "transmit"


def test_prefix_columns():
    df = pd.DataFrame({"col": ["x", None]})
    prefix_columns(df, ["col"], "P-")
    assert list(df["col"]) == ["P-x", None]


def test_aggregate_and_directional():
    df = pd.DataFrame({
        "direction": ["receive", "receive"],
        "source": ["a", "b"],
        "dest": ["b", "c"],
        "frames": [1, 2],
    })
    links = _aggregate_links(df, ["source", "dest"], "frames")
    assert links["Value"].sum() == 3
    labels, sources, targets, values, node_x = _compute_directional_sankey_data(
        df.rename(columns={"source": "l4_source", "dest": "l3_type"}),
        "receive",
        "frames",
    )
    assert set(labels) == {"a", "b", "c"}
    assert values == [1, 2]
    assert node_x is not None


def test_combined_and_compute():
    df = pd.DataFrame({
        "direction": ["receive", "transmit"],
        "source_mac": ["s1", "s2"],
        "destination_mac": ["d1", "d2"],
        "l2_type": ["T", "T"],
        "l3_source": ["192.168.0.1", "192.168.0.2"],
        "l3_destination": ["1.1.1.1", "1.1.1.2"],
        "l3_type": ["IP", "IP"],
        "l4_source": [1, 2],
        "l4_destination": [3, 4],
        "frames": [1, 1],
    })
    labels, *_ = _compute_combined_sankey_data(df, "frames", "eth0")
    assert "RX s1" in labels and "TX d2" in labels
    labels2, *_ = compute_sankey_data(df, "both", "frames", "eth0")
    assert labels == labels2


def test_create_and_update_sankey():
    df = pd.DataFrame({"direction": ["receive"], "frames": [1], "l4_source": ["a"], "l3_type": ["b"], "l3_source": ["c"], "l2_type": ["d"], "source_mac": ["e"], "destination_mac": ["f"]})
    fig = create_sankey_figure(df, "receive")
    assert fig.data[0].node.label[0] == "a"
    df2 = pd.DataFrame({"direction": ["receive"], "frames": [2], "l4_source": ["g"], "l3_type": ["h"], "l3_source": ["i"], "l2_type": ["j"], "source_mac": ["k"], "destination_mac": ["l"]})
    update_sankey_figure(fig, df2, "receive")
    assert "g" in fig.data[0].node.label
    fig2 = create_and_display_sankey_diagram(df, "receive")
    assert fig2.data[0].node.label[0] == "a"


def test_get_ip_scope():
    assert get_ip_scope("192.168.0.1") == "Private"
    assert get_ip_scope("127.0.0.1") == "Loopback"
    assert get_ip_scope("8.8.8.8") == "Global"
    assert get_ip_scope("224.0.0.1") == "Multicast"
    assert get_ip_scope("bad") == "Invalid IP Address"


def test_construct_dataframe_from_capture(fake_packet, monkeypatch):
    monkeypatch.setattr(ns, "determine_frame_direction", lambda pkt, m: ns.Direction.TRANSMIT)
    monkeypatch.setattr(ns, "determine_frame_scope", lambda pkt: ns.Scope.UNICAST)
    df = construct_dataframe_from_capture([fake_packet], {fake_packet.src: "eth0"})
    assert df.iloc[0]["direction"] == "transmit"
    assert df.iloc[0]["l3_source_scope"] == "Private"
    assert df.iloc[0]["l4_source"] == 1234
    assert str(df.iloc[0]["l2_type"]).startswith("0x0800")


def test_interface_mapping(monkeypatch):
    monkeypatch.setattr(ns, "get_if_list", lambda: ["i1"])
    monkeypatch.setattr(ns, "get_if_hwaddr", lambda iface: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ns, "get_if_addr", lambda iface: "1.1.1.1")
    assert create_mac_to_interface_mapping() == {"aa:bb:cc:dd:ee:ff": "i1"}
    assert create_ip_to_interface_mapping() == {"1.1.1.1": "i1"}

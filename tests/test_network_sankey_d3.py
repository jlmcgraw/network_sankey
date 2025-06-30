from pathlib import Path

import pandas as pd

import network_sankey_d3 as d3


def test_create_sankey_json():
    df = pd.DataFrame({
        "direction": ["receive"],
        "l4_source": ["a"],
        "l3_type": ["b"],
        "l3_source": ["c"],
        "l2_type": ["d"],
        "source_mac": ["e"],
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

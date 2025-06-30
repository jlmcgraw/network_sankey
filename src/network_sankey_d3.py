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
"""Serve a live-updating D3.js Sankey diagram of network traffic."""

from __future__ import annotations

import argparse
import json
import logging
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pandas as pd
from scapy.all import sniff

from network_sankey import (
    compute_sankey_data,
    construct_dataframe_from_capture,
    create_mac_to_interface_mapping,
)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
DATA_FILE = WEB_DIR / "data.json"


def create_sankey_json(
    df: pd.DataFrame, direction: str, metric: str, interface_label: str,
) -> dict:
    """Return Sankey JSON data for the given dataframe."""
    labels, sources, targets, values_list, node_x = compute_sankey_data(
        df, direction, metric, interface_label,
    )
    nodes = [
        {"name": label, **({"x": x} if node_x is not None else {})}
        for label, x in zip(labels, node_x or [], strict=False)
    ]
    links = [
        {"source": s, "target": t, "value": v}
        for s, t, v in zip(sources, targets, values_list, strict=False)
    ]
    return {"nodes": nodes, "links": links}


def serve(directory: Path, port: int) -> ThreadingHTTPServer:
    """Return a simple HTTP server serving ``directory`` on ``port``."""
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, directory=str(directory), **kwargs)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return server


def main() -> int:
    """Run a small HTTP server that updates ``data.json`` continuously."""
    parser = argparse.ArgumentParser(description="Display network traffic using D3.js")
    parser.add_argument("--interface", default="en0", help="Interface for live capture")
    parser.add_argument("--direction", choices=["transmit", "receive", "both"], default="transmit")
    parser.add_argument("--metric", choices=["frames", "length"], default="frames")
    parser.add_argument("--batch-size", type=int, default=100, help="Packets per capture batch")
    parser.add_argument("--port", type=int, default=8000, help="Port to serve the web UI")
    args = parser.parse_args()

    mac_map = create_mac_to_interface_mapping()
    df = pd.DataFrame()

    server = serve(WEB_DIR, args.port)
    logging.info("Serving on http://localhost:%s/index.html", args.port)

    try:
        while True:
            packets = sniff(iface=args.interface, count=args.batch_size, timeout=1)
            if packets:
                new_df = construct_dataframe_from_capture(packets, mac_map)
                df = pd.concat([df, new_df], ignore_index=True)
                sankey_json = create_sankey_json(df, args.direction, args.metric, args.interface)
                DATA_FILE.write_text(json.dumps(sankey_json))
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

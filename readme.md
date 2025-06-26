Display a Sankey diagram of network traffic into/out of an interface

## Getting Started
- Install wireshark
  - For MaCOS, its included BPF utility will allow you to capture packets as a regular user
- create and activate a venv
```commandline
pip install .
```


If you have uv installed you can execute this script directly
```bash
./src/network_sankey.py --help
```

### Live mode

Run the tool without a capture file to sniff packets continuously. The diagram will refresh automatically when using the `--dash` flag. Use `--direction both` to display inbound and outbound traffic together:

```bash
./src/network_sankey.py --interface en0 --dash --direction both
```

The figure starts empty and populates as traffic is captured. You can control how many packets are processed in each batch with `--batch-size`.
Use the **Pause** button to temporarily stop capturing traffic and **Clear** to reset the diagram.

## Todo
- Remove the TX/RX labels but still differentiate between RX/TX
- Consistent colors between updates
- A toggle for name resolution, or name resolution in the tooltip
- Dump packets for whatever is being hovered over
- Hovering over a node tracks its flow all the way back to the source and displays information about it
- Tooltips cover the flows
- Provide a rolling window of the capture (eg last 30 seconds)
- Display a diagram in native GUI without using browser
- Sort nodes

## Done
- Consistent node colors between updates
- Unified diagram ( in -> interface -> out)
- Capture pause/resume and clear buttons
- Display a running count of packets/frames/bytes in/out
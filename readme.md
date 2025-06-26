Display a Sankey diagram of network traffic into/out of an interface

## Getting Started
- Install wireshark
  - For MaCOS, its included BPF utility will allow you to capture packets as a regular user
- create/activate a venv
- pip install -r requirements.txt

If you have uv installed you can execute this script directly
```bash
./network_sankey.py --dash --interface en0 --direction both
```

### Live mode

Run the tool without a capture file to sniff packets continuously. The diagram will refresh automatically when using the `--dash` flag. Use `--direction both` to display inbound and outbound traffic together:

```bash
python network_sankey.py --interface en0 --dash --direction both
```

The figure starts empty and populates as traffic is captured. You can control how many packets are processed in each batch with `--batch-size`.

## Todo
- Consistent node colors between updates (eg hash them and map to color)
- Remove the TX/RX labels but still differentiate between RX/TX
- Consistent colors between updates
- A toggle for name resolution, or name resolution in the tooltip
- Dump packets for whatever is being hovered over
- Hovering over a node tracks its flow all the way back to the source and displays information about it
- Tooltips cover the flows
- Display a running count of packets/frames/bytes in/out
- Provide capture start/stop/clear buttons
- Provide a rolling window of the capture (eg last 30 seconds)
- Display a diagram in native GUI without using browser

## Done
- Unified diagram ( in -> interface -> out)
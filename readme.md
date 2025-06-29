Display a Sankey diagram of network traffic into/out of an interface

## Getting Started
- Install [homebrew](https://brew.sh/)
- Install uv
```commandline
brew install uv
```

- Install wireshark
  - For macOS, its included BPF utility will allow you to capture packets as a regular user
```commandline
brew install wireshark-app
```

With uv installed you can [execute the script directly](https://docs.astral.sh/uv/guides/scripts/#using-a-shebang-to-create-an-executable-file) 
```bash
./src/network_sankey.py --help
```

### Live mode

Run the tool without a capture file to sniff packets continuously. 

The diagram will refresh automatically when using the `--dash` flag. 

Use `--direction both` to display inbound and outbound traffic together:

```bash
./src/network_sankey.py --interface en0 --dash --direction both
```

The figure starts empty and populates as traffic is captured. 

You can control how many packets are processed in each batch with `--batch-size`.

Use the **Pause** button to temporarily stop capturing traffic and **Clear** to reset the diagram.

## Todo
- Fix how ports are displayed as floats
- Remove the TX/RX labels but still differentiate between RX/TX
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
- Correct L2 protocol placement in the diagram
  - Node positions are now fixed so L2 entries don't shift columns
### D3.js Interface

You can visualize traffic using a basic D3.js Sankey diagram. Start the server and open the web interface:

```bash
python src/network_sankey_d3.py --interface en0
```

The page is served at `http://localhost:8000/index.html` and refreshes automatically.

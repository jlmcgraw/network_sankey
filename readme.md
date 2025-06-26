Currently, this will load 4x Sankey diagrams in a web browser: traffic in/out by bytes/packets. A new live mode can capture packets continuously and update the diagram in real time.

In the future, I'd like to find methods to:
- Display a diagram in native GUI without using browser
- Have a live display of traffic
- Hover over traffic and display the full path of the flow and information about it

## Getting Started
- Install wireshark
  - For MaCOS, its included BPF utility will allow you to capture packets as a regular user
- create/activate a venv
- pip install -r requirements.txt
- pip install ipywidgets  # needed for live updating with the --dash flag

### Live mode

Run the tool without a capture file to sniff packets continuously. The diagram will refresh automatically when using the `--dash` flag:

```bash
python network_sankey.py --interface en0 --dash
```

The figure starts empty and populates as traffic is captured. You can control how many packets are processed in each batch with `--batch-size`.


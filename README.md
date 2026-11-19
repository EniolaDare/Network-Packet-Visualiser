# Single-file Network Packet Visualiser

An offline network packet dashboard contained in one Python source file:
`network_packet_visualiser.py`. It uses Scapy, Streamlit, Plotly and Pandas.
The sample capture is generated in memory, so no separate PCAP, helper modules
or configuration file is required. Third-party libraries must still be installed.

## What it does

- Upload PCAP or PCAPNG captures.
- Browse a paginated packet table and inspect decoded layers and raw bytes.
- Filter by protocol and an exact source/destination IPv4 or IPv6 address.
- View protocol distribution, top IPs and traffic over time.
- View a connection bubble map: bubble area represents each address's total
  packet bytes sent across the loaded capture, before filters. Lines follow
  filtered connections; their hover markers show direction, bytes and packets.
- Export all matching loaded packets to CSV.
- Try the built-in 108-packet synthetic sample without another file.

## Windows setup

Install Python 3.11 or 3.12 from https://www.python.org/downloads/windows/.
Enable **Add python.exe to PATH** during installation. Open a new PowerShell
window afterwards so it sees the updated PATH.

Open PowerShell in the folder containing `network_packet_visualiser.py` and run:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install "scapy>=2.6.1,<3" "streamlit>=1.40,<2" "plotly>=5.24,<7" "pandas>=2.2,<3"
.\.venv\Scripts\python.exe -m streamlit run network_packet_visualiser.py --global.developmentMode false --server.address 127.0.0.1 --server.maxUploadSize 25 --browser.gatherUsageStats false
```

Open http://127.0.0.1:8501/ if the browser does not open automatically.
Stop the app with Ctrl+C in PowerShell. On subsequent runs, only the last command
is needed. No activation or PowerShell execution-policy change is required.

If `python` is not recognised, install Python and reopen PowerShell, or use the
full path to your installed `python.exe`. If `python` opens the Microsoft Store,
use the actual installed Python executable. The `py` launcher is optional; if
installed, `py -3.12 -m venv .venv` can replace the environment creation command.
Do not continue to the `.venv` commands if creating the environment failed.

Administrator privileges and Npcap are not needed for offline capture reading.
An optional capture-driver warning from Scapy can be ignored for this app.

## Using the dashboard

1. The included sample opens automatically; choose **Upload capture** to use yours.
2. Set the maximum number of packets in the sidebar.
3. Select protocols and optionally enter one complete IP address. Empty protocol
   selection gives no matches. Partial addresses and CIDR filters are not supported.
4. Explore the bubble map, table and charts. Select a packet number for its details.
5. Choose **Download filtered CSV** to export matching rows from every table page.

All timestamps are UTC. The sample uses fixed timestamps starting 1 January 2025.
Map positions are a circular layout and do not represent geography. Receive-only
addresses have a minimum visible bubble, even with zero sent bytes. ARP protocol
addresses are included. Hover the small markers on lines to distinguish directions.

## How the code works

The single file contains three logical parts: Scapy parsing and Pandas analysis,
Plotly connection-map construction, and Streamlit presentation. Sample-generation
functions create packets in memory. The current parsed capture is retained in the
user's Streamlit session to avoid reparsing on every interaction. No local helper
Python files are imported.

The app only reads saved captures. It does not capture or send network packets,
decrypt traffic, or identify every application protocol. DNS is counted separately
from TCP/UDP; the remaining decoded protocols get exclusive labels. Byte totals
use original packet wire length when available, otherwise captured length, rather
than application payload size.

## Limits

- 25 MiB per uploaded file; enforced by both the parser and the launch command.
- Up to 20,000 analysed packets, with a warning when more packets exist.
- Captured records above 256 KiB are rejected.
- Map: at most 40 addresses ranked by total sent bytes, and 200 directed links.
  A warning reports omitted nodes/connections. Totals still include all loaded
  packets sent by displayed addresses.
- Packet table pages contain 250 rows; hex preview shows at most 2,048 bytes.
- When the packet limit is reached, capture-wide totals refer to the loaded subset.
- Empty time buckets are omitted to keep large timestamp gaps manageable.

Capture uploads stay in process/session memory; they are not saved by the app.
CSV text is escaped against spreadsheet formula injection. Parser errors get
friendly messages, but successful parsing does not certify file integrity. Use
trusted captures locally; the app is not an isolated hostile-file sandbox.

## Troubleshooting

- **Not Found page:** use the complete launch command, including
  `--global.developmentMode false`, then refresh the browser.
- **Port already in use:** append `--server.port 8502`; open http://127.0.0.1:8502/.
- **Missing library:** rerun the dependency installation using the same `.venv`
  Python executable used to start Streamlit.
- **No packets match:** clear the IP field and select the desired protocols.
- **Capture too large:** split it externally into smaller captures.

## Validation

The combined file was tested with Streamlit AppTest for sample loading, connection
map rendering, DNS filtering and invalid-IP handling. The modular source's eight
tests also passed before combination. This does not replace manual testing of
every capture format or a browser upload/download.

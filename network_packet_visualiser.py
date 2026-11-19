"""Standalone offline Network Packet Visualiser. See README.md for launch instructions."""


from dataclasses import dataclass
from io import BytesIO
import ipaddress
import math
import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, PcapReader
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_PACKETS = 20000
MAX_CAPTURED_PACKET = 262144
COLUMNS = ['number', 'timestamp', 'source', 'destination', 'protocol', 'source_port', 'destination_port', 'length', 'summary']
MAGICS = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'M<\xb2\xa1', b'\xa1\xb2<M', b'\n\r\r\n'}

class CaptureError(ValueError):
    """A capture cannot be analysed safely or meaningfully."""

@dataclass
class Capture:
    table: pd.DataFrame
    packets: list
    limited: bool

def protocol(packet):
    if DNS in packet:
        return 'DNS'
    if TCP in packet:
        return 'TCP'
    if UDP in packet:
        return 'UDP'
    if ICMP in packet:
        return 'ICMP'
    if any((layer.__name__.startswith('ICMPv6') for layer in packet.layers())):
        return 'ICMPv6'
    if ARP in packet:
        return 'ARP'
    if IPv6 in packet:
        return 'IPv6'
    if IP in packet:
        return 'IPv4'
    return 'Other'

def analyse_capture(data: bytes, max_packets=MAX_PACKETS) -> Capture:
    if not isinstance(max_packets, int) or not 1 <= max_packets <= MAX_PACKETS:
        raise CaptureError(f'Packet limit must be between 1 and {MAX_PACKETS:,}.')
    if not data:
        raise CaptureError('The capture is empty.')
    if len(data) > MAX_FILE_BYTES:
        raise CaptureError('Capture exceeds the 25 MB file limit.')
    if data[:4] not in MAGICS:
        raise CaptureError('This is not a supported PCAP or PCAPNG capture.')
    rows, packets = ([], [])
    limited = False
    try:
        with PcapReader(BytesIO(data)) as reader:
            for packet in reader:
                if len(packets) >= max_packets:
                    limited = True
                    break
                if len(packet.original) > MAX_CAPTURED_PACKET:
                    raise CaptureError('A packet exceeds the 256 KiB record limit.')
                timestamp = float(packet.time)
                if not math.isfinite(timestamp):
                    raise CaptureError('A packet has an invalid timestamp.')
                stamp = pd.to_datetime(timestamp, unit='s', utc=True, errors='coerce')
                if pd.isna(stamp):
                    raise CaptureError('A packet timestamp is outside the supported range.')
                network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
                arp = packet[ARP] if ARP in packet else None
                transport = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
                rows.append(dict(number=len(packets) + 1, timestamp=stamp, source=str(network.src) if network is not None else str(arp.psrc) if arp is not None else '', destination=str(network.dst) if network is not None else str(arp.pdst) if arp is not None else '', protocol=protocol(packet), source_port=int(transport.sport) if transport is not None else None, destination_port=int(transport.dport) if transport is not None else None, length=int(getattr(packet, 'wirelen', None) or len(packet)), summary=packet.summary()[:300]))
                packets.append(packet)
    except CaptureError:
        raise
    except Exception as exc:
        raise CaptureError('Cannot decode this capture. It may be damaged or use an unsupported format.') from exc
    frame = pd.DataFrame(rows, columns=COLUMNS)
    frame['timestamp'] = pd.to_datetime(frame['timestamp'], utc=True)
    for col in ['source_port', 'destination_port']:
        frame[col] = frame[col].astype('Int64')
    return Capture(frame, packets, limited)

def filter_packets(frame, protocols=None, ip_query='', direction='Either'):
    result = frame
    if protocols is not None:
        result = result[result.protocol.isin(protocols)]
    if ip_query.strip():
        try:
            address = str(ipaddress.ip_address(ip_query.strip()))
        except ValueError as exc:
            raise ValueError('Enter one complete IPv4 or IPv6 address.') from exc
        src, dst = (result.source.eq(address), result.destination.eq(address))
        result = result[src if direction == 'Source' else dst if direction == 'Destination' else src | dst]
    return result.copy()

def traffic_over_time(frame, interval='1s'):
    if interval not in {'1s', '10s', '1min', '5min', '1h', '1D'}:
        raise ValueError('Unsupported time interval.')
    return frame.assign(time=frame.timestamp.dt.floor(interval)).groupby('time', as_index=False).agg(packets=('number', 'size'), bytes=('length', 'sum'))

def top_ips(frame, limit=10):
    endpoints = pd.concat([frame.source, frame.destination])
    return endpoints[endpoints.ne('')].value_counts().head(limit).rename_axis('IP').reset_index(name='appearances')

def csv_bytes(frame):
    safe = frame.copy()
    for col in safe.select_dtypes(include=['object', 'string']).columns:
        safe[col] = safe[col].map(lambda x: "'" + x if isinstance(x, str) and x.lstrip().startswith(('=', '+', '-', '@')) else x)
    return safe.to_csv(index=False).encode('utf-8-sig')

import math
import pandas as pd
import plotly.graph_objects as go

def connection_data(frame, capture_frame, max_nodes=40, max_links=200):
    visible = frame[frame.source.ne('') & frame.destination.ne('')]
    links = visible.groupby(['source', 'destination'], as_index=False).agg(bytes=('length', 'sum'), packets=('number', 'size'))
    sent = capture_frame[capture_frame.source.ne('')].groupby('source').length.sum()
    addresses = set(visible.source) | set(visible.destination)
    ranked = sorted(addresses, key=lambda ip: (-int(sent.get(ip, 0)), ip))
    nodes = pd.DataFrame({'IP': ranked[:max_nodes]})
    nodes['sent_bytes'] = [int(sent.get(ip, 0)) for ip in nodes.IP]
    selected = set(nodes.IP)
    shown = links[links.source.isin(selected) & links.destination.isin(selected)]
    shown = shown.sort_values(['bytes', 'source', 'destination'], ascending=[False, True, True]).head(max_links)
    return (nodes, shown, len(addresses) - len(nodes), len(links) - len(shown))

def connection_figure(nodes, links):
    fig = go.Figure()
    if nodes.empty:
        return fig
    count = len(nodes)
    positions = {ip: (math.cos(2 * math.pi * i / count), math.sin(2 * math.pi * i / count)) for i, ip in enumerate(nodes.IP)}
    xs, ys = ([], [])
    mid_x, mid_y, descriptions = ([], [], [])
    for edge in links.itertuples():
        x1, y1 = positions[edge.source]
        x2, y2 = positions[edge.destination]
        if edge.source == edge.destination:
            angle = math.atan2(y1, x1)
            cx, cy = (x1 + 0.13 * math.cos(angle), y1 + 0.13 * math.sin(angle))
            line_x = [cx + 0.13 * math.cos(t * 2 * math.pi / 24) for t in range(25)]
            line_y = [cy + 0.13 * math.sin(t * 2 * math.pi / 24) for t in range(25)]
            mx, my = (cx + 0.13 * math.cos(angle), cy + 0.13 * math.sin(angle))
        else:
            line_x, line_y = ([x1, x2], [y1, y2])
            mx, my = (0.6 * x1 + 0.4 * x2, 0.6 * y1 + 0.4 * y2)
        xs.extend(line_x + [None])
        ys.extend(line_y + [None])
        mid_x.append(mx)
        mid_y.append(my)
        descriptions.append(f'{edge.source} → {edge.destination}<br>{edge.bytes:,} bytes · {edge.packets:,} packets')
    fig.add_trace(go.Scatter(x=xs, y=ys, mode='lines', line=dict(color='rgba(130,150,180,0.55)', width=2), hoverinfo='skip'))
    fig.add_trace(go.Scatter(x=mid_x, y=mid_y, mode='markers', marker=dict(size=9, color='#8496b4'), text=descriptions, hovertemplate='%{text}<extra></extra>'))
    maximum = max(int(nodes.sent_bytes.max()), 1)
    fig.add_trace(go.Scatter(x=[positions[ip][0] for ip in nodes.IP], y=[positions[ip][1] for ip in nodes.IP], mode='markers+text', text=nodes.IP.tolist(), textposition='top center', customdata=nodes[['sent_bytes']].to_numpy(), marker=dict(size=nodes.sent_bytes.tolist(), sizemode='area', sizeref=2 * maximum / 90 ** 2, sizemin=6, color=nodes.sent_bytes.tolist(), colorscale='Blues', line=dict(width=2, color='#55b9ed')), hovertemplate='%{text}<br>Total sent over loaded capture: %{customdata[0]:,} bytes<extra></extra>'))
    fig.update_layout(height=620, showlegend=False, dragmode='pan', margin=dict(l=50, r=50, t=40, b=40), xaxis=dict(visible=False, range=[-1.5, 1.5]), yaxis=dict(visible=False, range=[-1.5, 1.5], scaleanchor='x', scaleratio=1))
    return fig

from pathlib import Path
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap

def make_packets():
    packets = []
    for i in range(12):
        packets.extend([Ether() / ARP(psrc='192.168.1.10', pdst='192.168.1.1'), Ether() / IP(src='192.168.1.10', dst='192.0.2.53') / UDP(sport=53000 + i, dport=53) / DNS(id=i, qd=DNSQR(qname='example.test')), Ether() / IP(src='192.0.2.53', dst='192.168.1.10') / UDP(sport=53, dport=53000 + i) / DNS(id=i, qr=1, qd=DNSQR(qname='example.test'), an=DNSRR(rrname='example.test', rdata='198.51.100.20')), Ether() / IP(src='192.168.1.10', dst='198.51.100.20') / TCP(sport=40000 + i, dport=443, flags='S'), Ether() / IP(src='198.51.100.20', dst='192.168.1.10') / TCP(sport=443, dport=40000 + i, flags='SA'), Ether() / IP(src='192.168.1.10', dst='198.51.100.20') / TCP(sport=40000 + i, dport=443, flags='PA') / Raw(b'Synthetic encrypted-traffic placeholder'), Ether() / IP(src='192.168.1.10', dst='192.168.1.1') / ICMP(type=8), Ether() / IP(src='192.168.1.1', dst='192.168.1.10') / ICMP(type=0), Ether() / IPv6(src='2001:db8::10', dst='2001:db8::20') / UDP(sport=6000, dport=6001) / Raw(b'Synthetic IPv6 data')])
    for i, packet in enumerate(packets):
        packet[Ether].src = '02:00:00:00:00:10'
        packet[Ether].dst = '02:00:00:00:00:20'
        if ARP in packet:
            packet[ARP].hwsrc = '02:00:00:00:00:10'
            packet[ARP].hwdst = '00:00:00:00:00:00'
        packet.time = 1735689600 + i * 0.37
    return packets


def sample_bytes():
    """Generate the sample in memory; no companion capture file is needed."""
    from scapy.utils import PcapWriter
    buffer = BytesIO()
    writer = PcapWriter(buffer, sync=True)
    try:
        writer.write(make_packets())
        return buffer.getvalue()
    finally:
        writer.close()


"""Run with: python -m streamlit run app.py"""
from pathlib import Path
import plotly.express as px
import streamlit as st
st.set_page_config(page_title='Network Packet Visualiser', page_icon='🌐', layout='wide')
st.title('Network Packet Visualiser')
st.caption('Explore saved PCAP and PCAPNG captures. Times are UTC. No live capture or packet transmission.')
source = st.sidebar.radio('Capture source', ['Included sample', 'Upload capture'])
limit = st.sidebar.slider('Maximum packets to analyse', 100, MAX_PACKETS, 10000, 100)
data = None
if source == 'Upload capture':
    upload = st.sidebar.file_uploader('PCAP / PCAPNG (up to 25 MB)', type=['pcap', 'pcapng', 'cap'])
    if upload is not None:
        if upload.size > MAX_FILE_BYTES:
            st.error('Capture exceeds the 25 MB file limit.')
            st.stop()
        data = upload.getvalue()
else:
    data = sample_bytes()
if data is None:
    st.info('Choose a capture in the sidebar to begin.')
    st.stop()
key = (data, limit)
try:
    if st.session_state.get('capture_key') != key:
        with st.spinner('Reading packets…'):
            parsed = analyse_capture(data, limit)
        st.session_state['capture'] = parsed
        st.session_state['capture_key'] = key
    capture = st.session_state['capture']
except CaptureError as exc:
    st.error(str(exc))
    st.stop()
if capture.limited:
    st.warning(f'Only the first {limit:,} packets were analysed. All views and exports use this subset.')
if capture.table.empty:
    st.info('This capture contains no readable packets.')
    st.stop()
protocols = st.sidebar.multiselect('Protocols', sorted(capture.table.protocol.unique()), default=sorted(capture.table.protocol.unique()))
ip = st.sidebar.text_input('Exact IP address', placeholder='e.g. 192.168.1.10')
direction = st.sidebar.selectbox('IP direction', ['Either', 'Source', 'Destination'])
try:
    frame = filter_packets(capture.table, protocols, ip, direction)
except ValueError as exc:
    st.warning(str(exc))
    st.stop()
a, b, c = st.columns(3)
a.metric('Matching packets', f'{len(frame):,}')
b.metric('Packet bytes', f'{int(frame.length.sum()):,}')
duration = (frame.timestamp.max() - frame.timestamp.min()).total_seconds() if len(frame) else 0
c.metric('Time span', f'{duration:,.3f} s')
st.caption(f'{len(capture.table):,} packets loaded. Charts, table and CSV follow the sidebar filters.')
if frame.empty:
    st.info('No packets match these filters. Select a protocol or clear the IP filter.')
    st.stop()
st.subheader('Connection bubble map')
nodes, links, hidden_nodes, hidden_links = connection_data(frame, capture.table)
if nodes.empty:
    st.info('No IP or ARP endpoints in the matching packets.')
else:
    st.plotly_chart(connection_figure(nodes, links), use_container_width=True)
    st.caption('Each bubble is an IP address. Bubble area scales with total packet bytes sent over the entire loaded capture, before sidebar filters. Receive-only addresses have a small minimum bubble. Lines follow the current filters; hover a line marker for direction, bytes and packet count. Includes ARP addresses. Drag to pan and use the toolbar to zoom.')
    if hidden_nodes or hidden_links:
        st.warning(f'Map limited to 40 addresses and 200 directed connections for readability. {hidden_nodes:,} addresses and {hidden_links:,} connections omitted. Shown bubble totals still include all loaded packets sent by that address.')
st.subheader('Packet table')
page_size = 250
page = st.number_input('Table page', min_value=1, max_value=max(1, (len(frame) + page_size - 1) // page_size), value=1, step=1)
st.dataframe(frame.iloc[(page - 1) * page_size:page * page_size], hide_index=True, use_container_width=True)
st.download_button('Download filtered CSV', csv_bytes(frame), 'filtered_packets.csv', 'text/csv')
st.subheader('Packet detail inspector')
number = st.selectbox('Packet number (from filtered results)', frame.number.tolist(), format_func=lambda n: f'Packet {n}')
packet = capture.packets[int(number) - 1]
row = frame[frame.number.eq(number)].iloc[0]
st.write(f"{row['protocol']} · {row['source']} → {row['destination']} · {row['length']} bytes")
detail, raw = st.tabs(['Decoded layers', 'Raw bytes'])
with detail:
    st.code(packet.show(dump=True)[:24000], language='text')
with raw:
    payload = bytes(packet)
    st.caption('Hex preview limited to the first 2,048 captured bytes.')
    st.code(payload[:2048].hex(' '), language='text')
left, right = st.columns(2)
with left:
    st.subheader('Protocol distribution')
    counts = frame.protocol.value_counts().rename_axis('protocol').reset_index(name='packets')
    st.plotly_chart(px.pie(counts, names='protocol', values='packets', hole=0.45), use_container_width=True)
with right:
    st.subheader('Top IP addresses')
    ips = top_ips(frame)
    if ips.empty:
        st.info('No IP or ARP addresses in these packets.')
    else:
        st.plotly_chart(px.bar(ips, x='IP', y='appearances'), use_container_width=True)
    st.caption('Counts source and destination appearances, including ARP. An address can appear twice in a packet.')
st.subheader('Traffic over time')
interval = st.selectbox('Time bucket', ['1s', '10s', '1min', '5min', '1h', '1D'])
metric = st.radio('Traffic measure', ['packets', 'bytes'], horizontal=True)
traffic = traffic_over_time(frame, interval)
st.plotly_chart(px.bar(traffic, x='time', y=metric, labels={'time': 'Time (UTC)'}), use_container_width=True)
st.caption('Only buckets containing packets are included. Bytes use original wire length when available; payloads are not decrypted.')

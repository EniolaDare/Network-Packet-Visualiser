# Network Packet Visualiser - Product Backlog

**Project goal:** Build a simple Python application that lets users load saved network capture files, explore packets, filter traffic and view basic statistics.

**Technologies:** Python, Scapy, Streamlit and Plotly.

## Running the Project
1. Install the packages:

   ```bash
   pip install -r requirements.txt
   ```

2. Start the application:

   ```bash
   streamlit run main.py
   ```

## Product backlog

| ID | User story  |
|---|---|
| PB01 | As a user, I want to upload a `.pcap` or `.pcapng` file so that I can analyse saved network traffic. | 
| PB02 | As a user, I want the application to read packets from the uploaded file so that the capture can be explored. | 
| PB03 | As a user, I want to see a packet list containing the packet number, timestamp, source IP, destination IP, protocol and size. | 
| PB04 | As a user, I want to select a packet and inspect its details so that I can understand its headers. | 
| PB05 | As a user, I want to filter packets by protocol so that I can find TCP, UDP, ICMP or DNS traffic. | 
| PB06 | As a user, I want to filter packets by source or destination IP address so that I can examine traffic involving a particular device. | 
| PB07 | As a user, I want to see the total packet count and amount of data transferred so that I can understand the size of the capture. | 
| PB08 | As a user, I want to see a chart of protocol distribution so that I can understand which protocols are present. | 
| PB09 | As a user, I want to see the most active IP addresses so that I can identify the main communicating devices. | 
| PB10 | As a user, I want clear feedback when a file is invalid or cannot be read. | 
| PB11 | As a user, I want to clear filters and return to the full packet list. | 
| PB12 | As a user, I want a clear, organised interface so that the application is easy to use. | 
| PB13 | As a user, I want to inspect packet contents in hexadecimal format so that I can view the raw packet data. | 
| PB14 | As a user, I want to view traffic volume over time so that I can identify changes in network activity. | 
| PB15 | As a user, I want to export basic packet statistics so that I can use the results elsewhere. | 

## Scope boundaries

The first version will analyse capture files supplied by the user. It will not include:

- Live packet capture.
- Custom protocol decoding.
- Advanced TCP stream analysis.
- Network topology mapping.
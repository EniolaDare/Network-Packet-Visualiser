# Network Packet Visualiser — Sprint 1 Backlog

**Suggested duration:** 1 week 

## Sprint Goal

Create the basic application foundation, load a saved packet capture and display its packets in a simple table.


## Selected Product Backlog Items

| Product Backlog ID | Item | Priority |
|---|---|---|
| PB01 | Upload a PCAP/PCAPNG file | High |
| PB02 | Read packets from the uploaded file | High |
| PB03 | Display the basic packet list | High |
| PB10 | Show an error for an invalid or unreadable file | Medium |
| PB12 | Provide a basic, usable interface | Medium |

## Sprint Tasks

- [x] **S1-01:** Create the shared Git repository and agree on the initial folder structure.
- [x] **S1-02:** Set up the Python environment and install Streamlit and Scapy.
- [x] **S1-03:** Create the basic Streamlit application and page layout.
- [ ] **S1-04:** Add a file upload control for `.pcap` and `.pcapng` files.
- [ ] **S1-05:** Use Scapy to read packets from an uploaded capture file.
- [ ] **S1-06:** Extract packet number, timestamp, source IP, destination IP, protocol and size where available.
- [ ] **S1-07:** Display the extracted packet information in a table.
- [ ] **S1-08:** Handle invalid files, empty captures and packets without IP information.
- [ ] **S1-09:** Test the application using at least one valid capture file and one invalid file.
- [ ] **S1-10:** Review the code, merge changes and demonstrate the sprint result.
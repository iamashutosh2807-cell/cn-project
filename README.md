# Network Traffic Analyzer and Anomaly Detection System

**Jaypee Institute of Information Technology (JIIT) Noida**  
**Department of Computer Science & Engineering**  
**B.Tech CSE III-Year V Semester (2026-27)**  
**Course:** Computer Networks Project (PBL)

---

### 👥 Project Team
* **Ashutosh Das** – Enrollment No: `992401030215`
* **Dipanshu Thakur** – Enrollment No: `992401030216`
* **Prashant Tripathi** – Enrollment No: `992401030222`

**Submitted To:** **Prof. Madhav Bansal**, Department of CSE, JIIT Noida

---

## 📌 Project Overview
The **Network Traffic Analyzer and Anomaly Detection System** is a modular Python-based network monitoring and security diagnostic application. It ingests network traffic via live interface sniffing or offline `.pcap`/`.pcapng` packet captures, extracts protocol header metadata across the TCP/IP stack, aggregates statistical trends, and executes an explainable, rule-based anomaly detection engine.

All analytics are surfaced through an interactive **Streamlit** dashboard featuring Plotly data visualizations, Wireshark-like deep packet decodes, hex dumping, and instant academic PDF reporting.

```
                              ┌─────────────────────────────────────────┐
                              │           Packet Ingestion              │
                              │  • Offline PCAP/PCAPNG Uploads          │
                              │  • Live Interface Sniffing (Scapy)      │
                              │  • Pre-bundled Test Attack Scenarios    │
                              └────────────────────┬────────────────────┘
                                                   │
                                                   ▼
                              ┌─────────────────────────────────────────┐
                              │             Packet Parser               │
                              │  • Layer 2: Ethernet / ARP              │
                              │  • Layer 3: IPv4, IPv6, ICMP            │
                              │  • Layer 4: TCP (Flags, Seq, Ack), UDP  │
                              │  • Layer 7: DNS, HTTP, TLS              │
                              └────────────────────┬────────────────────┘
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼                                                   ▼
        ┌───────────────────────────────────┐               ┌───────────────────────────────────┐
        │       Statistical Analyzer        │               │      Anomaly Detection Engine     │
        │ • Total Volume, Rate, Duration    │               │ 1. Port Scan (Sliding Window)     │
        │ • Protocol Distribution           │               │ 2. Repeated Connection / SYN Flood│
        │ • Top Talkers & IP Flows          │               │ 3. Traffic Spike (Rate Bursts)    │
        │ • TCP Handshakes & Retransmission │               │ 4. ICMP Ping Flood                │
        │ • DNS Queries & Error Codes       │               │ 5. DNS NXDOMAIN & Query Flood     │
        └─────────────────┬─────────────────┘               │ 6. TCP Retransmissions            │
                          │                                 └─────────────────┬─────────────────┘
                          └─────────────────────────┬─────────────────────────┘
                                                    │
                                                    ▼
                              ┌─────────────────────────────────────────┐
                              │       Streamlit Interactive UI          │
                              │  • Overview & KPI Cards                 │
                              │  • Protocol & Size Distribution         │
                              │  • Conversation Matrix                  │
                              │  • TCP & DNS Deep Dive                  │
                              │  • Explainable Security Alerts          │
                              │  • Packet Inspector (Hex Dump Viewer)   │
                              │  • 1-Click PDF Report & CSV/JSON Export │
                              └─────────────────────────────────────────┘
```

---

## 🎯 Anomaly Detection Rules (Synopsis Section 3.3)

| Rule Name | Detection Logic | Severity | Possible False Positives |
| :--- | :--- | :---: | :--- |
| **1. Port Scan** | Single source host attempts connections to $\ge 15$ distinct ports on a destination within a 10s window. | `HIGH` | Authorized security vulnerability scanners, local network discovery (UPnP, mDNS). |
| **2. Repeated Connections (SYN Flood)** | High volume of TCP SYN packets from a source to destination with $< 15\%$ completed 3-way handshakes. | `HIGH` | Overloaded or offline server causing legitimate browser/client retries. |
| **3. Traffic Spike** | Instantaneous packet rate (PPS) exceeds $3.0\times$ the moving baseline average with $\ge 30$ PPS. | `MEDIUM` | Large OS/game updates, video stream buffering, automated database backups. |
| **4. ICMP Flood** | More than 25 ICMP Echo Requests sent from a single host within a 5-second interval. | `MEDIUM` | Network troubleshooting scripts (`ping -f`, `traceroute`), Path MTU discovery. |
| **5. DNS Anomaly** | Query rate $> 15$ queries/sec OR $\ge 5$ failed `NXDOMAIN` (Non-Existent Domain) responses to a host. | `HIGH` | Aggressive browser pre-fetching, ad-blockers redirecting domains, misconfigured apps. |
| **6. High Retransmissions** | Retransmission ratio on an active TCP flow exceeds $10\%$ with $\ge 15$ packets. | `LOW` | Congested Wi-Fi/cellular links, packet drops due to bufferbloat, physical link errors. |

---

## 🛠️ Directory Structure

```
PBL/
├── app.py                      # Main Streamlit Dashboard Application
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation & viva guide
├── core/
│   ├── __init__.py             # Package descriptor
│   ├── parser.py               # Scapy-based L2-L7 packet decoder & DataFrame extractor
│   ├── analyzer.py             # Traffic stats, top talkers, TCP handshakes, DNS analytics
│   ├── detector.py             # 6 explainable anomaly detection rules with tunable thresholds
│   ├── capture.py              # Thread-safe live sniffer with BPF filter support
│   ├── report_gen.py           # Automated academic PDF report generator (fpdf2)
│   └── sample_generator.py     # Generates realistic sample PCAPs for testing & demos
├── sample_pcaps/               # Bundled test scenarios
│   ├── normal_traffic.pcap     # Benign browsing, DNS, HTTP, ICMP, TLS
│   ├── port_scan.pcap          # 25-port reconnaissance scan
│   ├── syn_flood.pcap          # TCP SYN flood attack targeting port 80
│   ├── icmp_flood.pcap         # High-frequency ping flood
│   ├── dns_anomaly.pcap        # High-rate queries & NXDOMAIN responses (DGA simulation)
│   └── mixed_scenario.pcap     # Comprehensive mixed traffic for presentations
└── tests/
    ├── __init__.py
    └── test_engine.py          # Unit & integration test suite (100% passing)
```

---

## 🚀 Setup and Execution

### 1. Prerequisites
Ensure Python 3.10+ is installed on your system.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Dashboard
```bash
streamlit run app.py
```
The dashboard will open automatically in your browser at `http://localhost:8501`.

### 4. Run Automated Unit Tests
```bash
python -m unittest tests/test_engine.py
```

---

## 🧪 Demonstration & Viva Guide

1. **Select a Demo Scenario**:
   In the sidebar, choose from pre-bundled scenarios:
   - **Normal Traffic**: Shows standard web browsing, clean metrics, and 0 security alerts.
   - **Port Scan Attack**: Demonstrates detection of multi-port probing (`RULE_01_PORT_SCAN`) with scanned port listing.
   - **TCP SYN Flood**: Demonstrates half-open handshake exhaustion (`RULE_02_SYN_FLOOD`).
   - **DNS Anomaly**: Demonstrates DGA / NXDOMAIN surge detection (`RULE_05_DNS_NXDOMAIN_SURGE`).
   - **Mixed Security Scenario**: Demonstrates realistic multi-protocol environment with background traffic and simultaneous anomalies.

2. **Explore Tabs**:
   - **Overview**: High-level KPIs, protocol share donut chart, traffic timeline.
   - **Protocol Analysis**: Packet length distribution, min/max/average MTU sizes.
   - **Hosts & Flows**: Top talkers and IP-to-IP conversation pairs.
   - **TCP & DNS Deep Dive**: TCP handshake completion rates, flag breakdown, DNS query logs.
   - **Anomaly Detection**: Expand alerts to view concrete evidence, detection logic, false positive analysis, and mitigations.
   - **Packet Inspector**: Click on any packet number to see full protocol layers and raw hex dump.
   - **Export & Report**: Click **"Generate & Download PDF"** to get a report ready for submission.

---

## 📚 References & Standards
- **RFC 791**: Internet Protocol (IPv4) Specification
- **RFC 793**: Transmission Control Protocol (TCP) Specification
- **RFC 1035**: Domain Names - Implementation and Specification
- **Kurose & Ross**: *Computer Networking: A Top-Down Approach*
- **Scapy Documentation**: Packet crafting, sniffing, and parsing in Python
- **Streamlit Documentation**: Interactive data visualization application framework

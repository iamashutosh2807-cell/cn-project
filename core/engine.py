import os, re, time, threading, tempfile
from collections import deque, defaultdict
from datetime import datetime
import pandas as pd
import numpy as np
from scapy.all import (
    sniff, get_if_list, rdpcap, PcapReader,
    IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
)

HTTP_REQ_RE = re.compile(br"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/\d\.\d", re.IGNORECASE)
HTTP_RESP_RE = re.compile(br"^HTTP/\d\.\d\s+(\d{3})\s+(.+)", re.IGNORECASE)
HTTP_HOST_RE = re.compile(br"(?:^|\r\n)Host:\s*([^\r\n]+)", re.IGNORECASE)
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

DEFAULT_THRESHOLDS = {
    "port_scan_min_ports": 15, "port_scan_window_sec": 10.0,
    "syn_flood_min_syns": 15, "syn_flood_max_completion_ratio": 0.15,
    "traffic_spike_multiplier": 3.0, "traffic_spike_min_pps": 30,
    "icmp_flood_min_packets": 25, "icmp_flood_window_sec": 5.0,
    "dns_query_rate_pps": 15.0, "dns_nxdomain_threshold": 5,
    "retransmission_threshold_pct": 10.0, "retransmission_min_packets": 15
}


class LiveCaptureSession:
    def __init__(self, max_buffer=10000):
        self.packets = deque(maxlen=max_buffer)
        self.is_capturing = False
        self.thread = None
        self.lock = threading.Lock()
        self.error_message = None
        self.start_time = None
        self.packet_limit = 0

    @staticmethod
    def get_available_interfaces():
        try:
            ifaces = get_if_list()
            return ifaces if ifaces else ["Default"]
        except Exception:
            return ["Default"]

    def _packet_handler(self, pkt):
        with self.lock:
            self.packets.append(pkt)
            if 0 < self.packet_limit <= len(self.packets):
                self.is_capturing = False

    def _sniff_worker(self, iface, bpf_filter, count, timeout):
        try:
            kw = {"prn": self._packet_handler, "store": False, "stop_filter": lambda _: not self.is_capturing}
            if iface and iface != "Default": kw["iface"] = iface
            if bpf_filter and bpf_filter.strip(): kw["filter"] = bpf_filter.strip()
            if count and count > 0: kw["count"] = count
            if timeout and timeout > 0: kw["timeout"] = timeout
            sniff(**kw)
        except Exception as e:
            self.error_message = str(e)
        finally:
            self.is_capturing = False

    def start(self, iface=None, bpf_filter=None, count=0, timeout=None):
        if self.is_capturing:
            return False, "Capture already running"
        with self.lock:
            self.packets.clear()
            self.error_message, self.is_capturing, self.start_time, self.packet_limit = None, True, time.time(), count or 0
        self.thread = threading.Thread(target=self._sniff_worker, args=(iface, bpf_filter, count, timeout), daemon=True)
        self.thread.start()
        return True, "Capture started"

    def stop(self):
        self.is_capturing = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        return len(self.packets)

    def get_status(self):
        with self.lock:
            dur = round(time.time() - self.start_time, 1) if self.start_time else 0.0
            return {"is_capturing": self.is_capturing, "packet_count": len(self.packets), "duration": dur, "error": self.error_message}

    def get_packets(self):
        with self.lock:
            return list(self.packets)


def parse_tcp_flags(flags_val):
    if not flags_val: return ""
    s = str(flags_val)
    fmap = [("FIN", "F"), ("SYN", "S"), ("RST", "R"), ("PSH", "P"), ("ACK", "A"), ("URG", "U"), ("ECE", "E"), ("CWR", "C")]
    names = [name for name, ch in fmap if ch in s]
    return "-".join(names) if names else s


def parse_packet(pkt, pkt_idx, first_epoch=None):
    try: epoch = float(pkt.time)
    except Exception: epoch = 0.0
    first_epoch = epoch if first_epoch is None else first_epoch

    src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack = "Unknown", "Unknown", None, None, None, None
    protocol, tcp_flags, info = "Other", "", ""
    dns_query, dns_qtype, dns_rcode, dns_is_resp = None, None, None, False
    http_method, http_uri, http_host, http_status = None, None, None, None

    if IP in pkt: src_ip, dst_ip, protocol = pkt[IP].src, pkt[IP].dst, "IPv4"
    elif IPv6 in pkt: src_ip, dst_ip, protocol = pkt[IPv6].src, pkt[IPv6].dst, "IPv6"
    elif ARP in pkt:
        src_ip, dst_ip, protocol = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"
        info = f"ARP {'Request' if pkt[ARP].op == 1 else 'Reply'}: {src_ip} -> {dst_ip}"

    if ICMP in pkt:
        protocol = "ICMP"
        info = f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}"
    elif TCP in pkt:
        protocol, src_port, dst_port = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
        tcp_flags, tcp_seq, tcp_ack = parse_tcp_flags(pkt[TCP].flags), int(pkt[TCP].seq), int(pkt[TCP].ack)
        info = f"{src_port} -> {dst_port} [{tcp_flags}] Seq={tcp_seq} Ack={tcp_ack}"
        if 53 in (src_port, dst_port): protocol = "DNS"
        elif any(p in (80, 8080) for p in (src_port, dst_port)): protocol = "HTTP"
        elif any(p in (443, 8443) for p in (src_port, dst_port)): protocol = "TLS/HTTPS"
    elif UDP in pkt:
        protocol, src_port, dst_port = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
        info = f"{src_port} -> {dst_port} Len={pkt[UDP].len}"
        if 53 in (src_port, dst_port): protocol = "DNS"
        elif any(p in (67, 68) for p in (src_port, dst_port)): protocol = "DHCP"
        elif 123 in (src_port, dst_port): protocol = "NTP"
        elif 443 in (src_port, dst_port): protocol = "QUIC"

    if DNS in pkt:
        protocol, dns_is_resp = "DNS", bool(pkt[DNS].qr)
        dns_rcode = DNS_RCODES.get(pkt[DNS].rcode, f"RCODE_{pkt[DNS].rcode}")
        qd = pkt[DNS].qd
        item = qd[0] if isinstance(qd, (list, tuple)) and len(qd) > 0 else qd
        if item and hasattr(item, "qname"):
            try:
                qn = item.qname
                dns_query = (qn.decode('utf-8', 'ignore') if isinstance(qn, bytes) else str(qn)).rstrip('.')
                dns_qtype = DNS_TYPES.get(getattr(item, "qtype", None), "A")
            except Exception: pass
        info = f"DNS {'Resp' if dns_is_resp else 'Query'}: {dns_query or ''} [{dns_rcode if dns_is_resp else dns_qtype}]"

    if Raw in pkt and protocol in ("TCP", "HTTP"):
        payload = bytes(pkt[Raw].load)
        m = HTTP_REQ_RE.match(payload)
        if m:
            protocol, http_method, http_uri = "HTTP", m.group(1).decode('ascii', 'ignore'), m.group(2).decode('ascii', 'ignore')
            hm = HTTP_HOST_RE.search(payload)
            if hm: http_host = hm.group(1).decode('ascii', 'ignore').strip()
            info = f"HTTP {http_method} {http_uri}"
        rm = HTTP_RESP_RE.match(payload)
        if rm:
            protocol, http_status = "HTTP", int(rm.group(1).decode('ascii', 'ignore'))
            info = f"HTTP/1.1 {http_status} {rm.group(2).decode('latin-1', 'ignore')}"

    return {
        "packet_num": pkt_idx, "epoch": epoch,
        "timestamp": datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if epoch > 0 else "N/A",
        "relative_time": round(max(0.0, epoch - first_epoch), 4),
        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol, "length": len(pkt), "tcp_flags": tcp_flags,
        "tcp_seq": tcp_seq, "tcp_ack": tcp_ack, "info": info or pkt.summary(),
        "dns_query": dns_query, "dns_qtype": dns_qtype, "dns_rcode": dns_rcode,
        "dns_is_response": dns_is_resp, "http_method": http_method,
        "http_uri": http_uri, "http_host": http_host, "http_status": http_status
    }


def parse_pcap_source(source, max_packets=None):
    raw_packets, temp_path = [], None
    try:
        if hasattr(source, "read") or isinstance(source, bytes):
            sfx = ".pcapng" if getattr(source, "name", "").endswith(".pcapng") else ".pcap"
            with tempfile.NamedTemporaryFile(delete=False, suffix=sfx) as tmp:
                tmp.write(source.read() if hasattr(source, "read") else source)
                temp_path = tmp.name
            target = temp_path
        elif isinstance(source, list):
            raw_packets = source[:max_packets] if max_packets else list(source)
            target = None
        else:
            target = str(source)

        if target:
            if max_packets:
                for pkt in PcapReader(target):
                    raw_packets.append(pkt)
                    if len(raw_packets) >= max_packets: break
            else:
                raw_packets = rdpcap(target)

        if not raw_packets: return pd.DataFrame(), []
        fe = float(getattr(raw_packets[0], 'time', 0.0))
        return pd.DataFrame([parse_packet(p, i, fe) for i, p in enumerate(raw_packets, 1)]), raw_packets
    finally:
        if temp_path and os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass


def get_packet_details(pkt):
    layers, cur = [], pkt
    while cur:
        flds = {f.name: (cur.getfieldval(f.name).decode('utf-8', 'replace') if isinstance(cur.getfieldval(f.name), bytes) else str(cur.getfieldval(f.name))) for f in cur.fields_desc}
        layers.append({"layer": cur.__class__.__name__, "fields": flds})
        cur = cur.payload if cur.payload and cur.payload.__class__.__name__ != 'NoPayload' else None

    raw = bytes(pkt)
    hex_lines = [f"{i:04x}   {' '.join(f'{b:02x}' for b in raw[i:i+16]):<48}   {''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[i:i+16])}" for i in range(0, len(raw), 16)]
    return {"summary": pkt.summary(), "layers": layers, "hex_dump": "\n".join(hex_lines)}


def compute_summary_metrics(df):
    if df.empty:
        return {k: 0 for k in ["total_packets", "total_bytes", "duration_sec", "avg_packet_rate",
                              "avg_byte_rate_kbps", "avg_packet_size", "min_packet_size",
                              "max_packet_size", "std_packet_size", "unique_src_ips",
                              "unique_dst_ips", "unique_protocols"]}
    n, total_bytes = len(df), int(df["length"].sum())
    dur = max(1.0, float(df["relative_time"].max() - df["relative_time"].min()))
    return {
        "total_packets": n, "total_bytes": total_bytes, "duration_sec": round(dur, 2),
        "avg_packet_rate": round(n / dur, 2), "avg_byte_rate_kbps": round((total_bytes * 8) / (dur * 1000), 2),
        "avg_packet_size": round(float(df["length"].mean()), 2),
        "min_packet_size": int(df["length"].min()), "max_packet_size": int(df["length"].max()),
        "std_packet_size": round(float(df["length"].std() if n > 1 else 0.0), 2),
        "unique_src_ips": df[df["src_ip"] != "Unknown"]["src_ip"].nunique(),
        "unique_dst_ips": df[df["dst_ip"] != "Unknown"]["dst_ip"].nunique(),
        "unique_protocols": df["protocol"].nunique()
    }


def compute_protocol_distribution(df):
    if df.empty: return pd.DataFrame(columns=["protocol", "packets", "bytes", "pct_packets", "pct_bytes"])
    g = df.groupby("protocol").agg(packets=("packet_num", "count"), bytes=("length", "sum")).reset_index()
    g["pct_packets"] = (g["packets"] / len(df) * 100).round(2)
    g["pct_bytes"] = (g["bytes"] / max(1, df["length"].sum()) * 100).round(2)
    return g.sort_values("packets", ascending=False).reset_index(drop=True)


def compute_top_talkers(df, top_n=10):
    if df.empty: return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    v = df[(df["src_ip"] != "Unknown") & (df["dst_ip"] != "Unknown")]
    src = v.groupby("src_ip").agg(packets=("packet_num", "count"), bytes=("length", "sum")).reset_index().sort_values("packets", ascending=False).head(top_n)
    dst = v.groupby("dst_ip").agg(packets=("packet_num", "count"), bytes=("length", "sum")).reset_index().sort_values("packets", ascending=False).head(top_n)
    flows = v.groupby(["src_ip", "dst_ip"]).agg(packets=("packet_num", "count"), bytes=("length", "sum"), dominant_protocol=("protocol", lambda x: x.mode()[0] if not x.empty else "N/A")).reset_index().sort_values("packets", ascending=False).head(top_n)
    return src, dst, flows


def compute_traffic_timeline(df, interval_sec=1.0):
    if df.empty: return pd.DataFrame(columns=["time_bucket", "packets", "bytes", "kbps"])
    iv = max(0.1, float(interval_sec))
    df_copy = df.copy()
    df_copy["time_bucket"] = (df_copy["relative_time"] // iv) * iv
    tl = df_copy.groupby("time_bucket").agg(packets=("packet_num", "count"), bytes=("length", "sum")).reset_index()
    tl["kbps"] = ((tl["bytes"] * 8) / (iv * 1000)).round(2)
    tl["time_bucket"] = tl["time_bucket"].round(2)
    return tl.sort_values("time_bucket").reset_index(drop=True)


def compute_tcp_statistics(df):
    tcp_df = df[df["tcp_seq"].notna() & df["src_port"].notna() & df["dst_port"].notna()].copy()
    if tcp_df.empty:
        return {"total_tcp_packets": 0, "flag_counts": {}, "connections": pd.DataFrame(),
                "retransmission_count": 0, "retransmission_rate_pct": 0.0,
                "handshake_stats": {"established": 0, "incomplete": 0, "reset": 0}}

    fl = tcp_df["tcp_flags"].dropna().tolist()
    flag_counts = {
        "SYN": sum(1 for f in fl if "SYN" in f and "ACK" not in f),
        "SYN-ACK": sum(1 for f in fl if "SYN" in f and "ACK" in f),
        "ACK": sum(1 for f in fl if f == "ACK"), "FIN": sum(1 for f in fl if "FIN" in f),
        "RST": sum(1 for f in fl if "RST" in f), "PSH-ACK": sum(1 for f in fl if "PSH" in f and "ACK" in f)
    }

    tcp_df["flow_id"] = tcp_df.apply(lambda r: f"{min(r['src_ip'], r['dst_ip'])}:{min(int(r['src_port']), int(r['dst_port']))} <-> {max(r['src_ip'], r['dst_ip'])}:{max(int(r['src_port']), int(r['dst_port']))}", axis=1)

    conns, est, inc, rst_cnt = [], 0, 0, 0
    for fid, grp in tcp_df.groupby("flow_id"):
        flg_seen = {x for f in grp["tcp_flags"] if f for x in f.split("-")}
        has_syn, has_sa, has_ack, has_rst, has_fin = "SYN" in flg_seen, any("SYN" in f and "ACK" in f for f in grp["tcp_flags"]), "ACK" in flg_seen, "RST" in flg_seen, "FIN" in flg_seen
        if has_syn and has_sa and has_ack: state, est = "ESTABLISHED", est + 1
        elif has_rst: state, rst_cnt = "RESET", rst_cnt + 1
        elif has_fin: state, est = "CLOSED/FIN", est + 1
        elif has_syn and not has_sa: state, inc = "INCOMPLETE (SYN Sent)", inc + 1
        else: state, est = "ESTABLISHED (Mid-stream)", est + 1
        conns.append({"flow": fid, "state": state, "packets": len(grp), "bytes": grp["length"].sum(), "has_rst": has_rst, "has_fin": has_fin})

    conn_df = pd.DataFrame(conns).sort_values("packets", ascending=False).reset_index(drop=True) if conns else pd.DataFrame()
    seq_df = tcp_df[(tcp_df["length"] > 54) | tcp_df["tcp_flags"].str.contains("SYN", na=False)]
    retx = int(seq_df.duplicated(subset=["src_ip", "dst_ip", "src_port", "dst_port", "tcp_seq"], keep="first").sum()) if not seq_df.empty else 0

    return {
        "total_tcp_packets": len(tcp_df), "flag_counts": flag_counts, "connections": conn_df,
        "retransmission_count": retx, "retransmission_rate_pct": round(retx / len(tcp_df) * 100, 2) if len(tcp_df) > 0 else 0.0,
        "handshake_stats": {"established": est, "incomplete": inc, "reset": rst_cnt}
    }


def compute_dns_statistics(df):
    dns_df = df[df["protocol"] == "DNS"].copy()
    if dns_df.empty:
        return {"total_dns_packets": 0, "total_queries": 0, "total_responses": 0,
                "top_domains": pd.DataFrame(), "query_types": pd.DataFrame(),
                "response_codes": pd.DataFrame(), "failed_queries": pd.DataFrame()}

    q = dns_df[~dns_df["dns_is_response"] & dns_df["dns_query"].notna()]
    r = dns_df[dns_df["dns_is_response"]]
    top_d = q["dns_query"].value_counts().reset_index() if not q.empty else pd.DataFrame(columns=["domain", "query_count"])
    top_d.columns = ["domain", "query_count"]
    qtypes = dns_df["dns_qtype"].value_counts().reset_index() if not dns_df["dns_qtype"].dropna().empty else pd.DataFrame(columns=["qtype", "count"])
    qtypes.columns = ["qtype", "count"]
    rcodes = r["dns_rcode"].value_counts().reset_index() if not r["dns_rcode"].dropna().empty else pd.DataFrame(columns=["rcode", "count"])
    rcodes.columns = ["rcode", "count"]
    failed = r[r["dns_rcode"].isin(["NXDOMAIN", "SERVFAIL", "REFUSED"])][["timestamp", "src_ip", "dst_ip", "dns_query", "dns_rcode"]].reset_index(drop=True)

    return {
        "total_dns_packets": len(dns_df), "total_queries": len(q), "total_responses": len(r),
        "top_domains": top_d.head(10), "query_types": qtypes, "response_codes": rcodes, "failed_queries": failed
    }


class AnomalyDetector:
    def __init__(self, thresholds=None):
        self.th = DEFAULT_THRESHOLDS.copy()
        if thresholds: self.th.update(thresholds)

    def detect_all(self, df):
        if df.empty: return []
        alerts = []
        alerts.extend(self._detect_port_scans(df))
        alerts.extend(self._detect_repeated_connections(df))
        alerts.extend(self._detect_traffic_spikes(df))
        alerts.extend(self._detect_icmp_flood(df))
        alerts.extend(self._detect_dns_anomalies(df))
        alerts.extend(self._detect_high_retransmissions(df))
        s_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(alerts, key=lambda a: (s_rank.get(a["severity"], 5), a["time_start"]))

    def _detect_port_scans(self, df):
        alerts = []
        conns = df[df["dst_port"].notna() & (df["src_ip"] != "Unknown") & (df["dst_ip"] != "Unknown")]
        min_p, win = self.th["port_scan_min_ports"], self.th["port_scan_window_sec"]

        for (src_ip, dst_ip), grp in conns.groupby(["src_ip", "dst_ip"]):
            sg = grp.sort_values("relative_time")
            times, ports, n = sg["relative_time"].values, sg["dst_port"].values, len(sg)
            left, flagged = 0, False
            for right in range(n):
                while times[right] - times[left] > win and left < right: left += 1
                wports = set(ports[left:right+1])
                if len(wports) >= min_p:
                    dur = round(float(times[right] - times[left]), 2)
                    pstr = ", ".join(str(int(p)) for p in sorted(list(wports))[:10])
                    alerts.append({
                        "rule_id": "RULE_01_PORT_SCAN", "rule_name": "Port Scan Detected", "severity": "HIGH",
                        "source_ip": src_ip, "target_ip": dst_ip,
                        "time_start": round(float(times[left]), 2), "time_end": round(float(times[right]), 2),
                        "evidence": f"{len(wports)} unique destination ports probed in {dur}s (threshold: {min_p}). Ports: [{pstr}].",
                        "reason": "Host initiated connections across multiple distinct destination ports in a brief interval.",
                        "false_positive": "Authorized vulnerability scanners or network discovery tools.",
                        "mitigation": "Check if source IP is an authorized scanner; block or rate-limit at firewall if hostile."
                    })
                    flagged = True
                    break

            if not flagged and len(set(ports)) >= min_p:
                dur = float(times[-1] - times[0]) if n > 1 else 0.0
                if dur <= win * 2 or dur == 0:
                    alerts.append({
                        "rule_id": "RULE_01_PORT_SCAN", "rule_name": "Port Scan Detected (Session Aggregate)", "severity": "HIGH",
                        "source_ip": src_ip, "target_ip": dst_ip,
                        "time_start": round(float(times[0]), 2), "time_end": round(float(times[-1]), 2),
                        "evidence": f"{len(set(ports))} unique ports probed across {round(dur, 2)}s.",
                        "reason": "Aggregated scanning activity mapped multiple target ports.",
                        "false_positive": "Network discovery services.",
                        "mitigation": "Review firewall ACL rules and investigate source IP credentials."
                    })
        return alerts

    def _detect_repeated_connections(self, df):
        alerts = []
        tcp_df = df[df["tcp_flags"].str.len() > 0].copy()
        if tcp_df.empty: return alerts

        min_syns, max_r = self.th["syn_flood_min_syns"], self.th["syn_flood_max_completion_ratio"]
        sa_counts = tcp_df[tcp_df["tcp_flags"].str.contains("SYN", na=False) & tcp_df["tcp_flags"].str.contains("ACK", na=False)].groupby(["src_ip", "dst_ip"]).size().to_dict()

        for (src_ip, dst_ip), grp in tcp_df.groupby(["src_ip", "dst_ip"]):
            if src_ip == "Unknown" or dst_ip == "Unknown": continue
            syns = grp[grp["tcp_flags"].str.contains("SYN", na=False) & ~grp["tcp_flags"].str.contains("ACK", na=False)]
            total_syns = len(syns)
            if total_syns >= min_syns:
                syn_acks = sa_counts.get((dst_ip, src_ip), 0)
                comp_ratio = syn_acks / total_syns if total_syns > 0 else 0.0
                if comp_ratio <= max_r:
                    t_start, t_end = round(float(syns["relative_time"].min()), 2), round(float(syns["relative_time"].max()), 2)
                    rate = round(total_syns / max(0.1, t_end - t_start), 1)
                    alerts.append({
                        "rule_id": "RULE_02_SYN_FLOOD", "rule_name": "Repeated Connection Attempts (SYN Flood / Half-Open)", "severity": "HIGH",
                        "source_ip": src_ip, "target_ip": dst_ip, "time_start": t_start, "time_end": t_end,
                        "evidence": f"{total_syns} SYN packets with only {syn_acks} SYN-ACK responses ({round(comp_ratio*100, 1)}% completion, {rate} SYN/s).",
                        "reason": "Host sent repeated TCP connection initiations without completing the three-way handshake.",
                        "false_positive": "A busy or temporarily unavailable server causing legitimate clients to retry.",
                        "mitigation": "Enable TCP SYN Cookies on target host and apply rate-limiting per source IP."
                    })
        return alerts

    def _detect_traffic_spikes(self, df):
        if len(df) < 20: return []
        mult, min_pps = self.th["traffic_spike_multiplier"], self.th["traffic_spike_min_pps"]
        dur = float(df["relative_time"].max() - df["relative_time"].min())
        if dur <= 1.0: return []

        df_copy = df.copy()
        df_copy["sec"] = df_copy["relative_time"].astype(int)
        bins = df_copy.groupby("sec").agg(packets=("packet_num", "count"), bytes=("length", "sum")).reset_index()
        avg_pps = bins["packets"].mean()

        alerts = []
        for _, row in bins.iterrows():
            sec, pps, bps = int(row["sec"]), row["packets"], row["bytes"]
            if pps >= min_pps and pps >= (avg_pps * mult):
                src_top = df_copy[df_copy["sec"] == sec]["src_ip"].value_counts().index[0]
                alerts.append({
                    "rule_id": "RULE_03_TRAFFIC_SPIKE", "rule_name": "Traffic Spike Detected", "severity": "MEDIUM",
                    "source_ip": src_top, "target_ip": "Network-wide", "time_start": float(sec), "time_end": float(sec + 1),
                    "evidence": f"Traffic reached {pps} pkts/s ({round(bps/1024, 1)} KB/s), {round(pps/max(1, avg_pps), 1)}x baseline ({round(avg_pps, 1)} pkts/s).",
                    "reason": "Transmission rate spiked dramatically above baseline moving average.",
                    "false_positive": "Large legitimate file download, OS update, or scheduled backup.",
                    "mitigation": "Verify whether high traffic corresponds to an approved scheduled data transfer."
                })
        return alerts

    def _detect_icmp_flood(self, df):
        icmp_df = df[df["protocol"] == "ICMP"]
        if icmp_df.empty: return []
        min_p, win = self.th["icmp_flood_min_packets"], self.th["icmp_flood_window_sec"]
        alerts = []
        for src_ip, grp in icmp_df.groupby("src_ip"):
            if src_ip == "Unknown": continue
            sg = grp.sort_values("relative_time")
            times, n, left = sg["relative_time"].values, len(sg), 0
            for right in range(n):
                while times[right] - times[left] > win and left < right: left += 1
                cnt = right - left + 1
                if cnt >= min_p:
                    t0, t1 = round(float(times[left]), 2), round(float(times[right]), 2)
                    rate = round(cnt / max(0.1, t1 - t0), 1)
                    target = sg["dst_ip"].mode()[0] if not sg.empty else "N/A"
                    alerts.append({
                        "rule_id": "RULE_04_ICMP_FLOOD", "rule_name": "ICMP Flood / Ping Sweep", "severity": "MEDIUM",
                        "source_ip": src_ip, "target_ip": target, "time_start": t0, "time_end": t1,
                        "evidence": f"{cnt} ICMP packets sent in {round(t1 - t0, 2)}s ({rate} pkts/s, threshold: {min_p}).",
                        "reason": "Host generated an unusually high volume of ICMP packets within a narrow window.",
                        "false_positive": "Network troubleshooting with ping or traceroute scripts.",
                        "mitigation": "Rate limit ICMP Echo Requests at border switches and firewalls."
                    })
                    break
        return alerts

    def _detect_dns_anomalies(self, df):
        dns_df = df[df["protocol"] == "DNS"]
        if dns_df.empty: return []
        max_rate, nx_th = self.th["dns_query_rate_pps"], self.th["dns_nxdomain_threshold"]
        alerts = []

        q = dns_df[~dns_df["dns_is_response"] & dns_df["dns_query"].notna()]
        for src_ip, grp in q.groupby("src_ip"):
            if src_ip == "Unknown": continue
            dur = float(grp["relative_time"].max() - grp["relative_time"].min())
            cnt = len(grp)
            rate = round(cnt / max(1.0, dur), 1)
            if cnt >= 10 and rate >= max_rate:
                alerts.append({
                    "rule_id": "RULE_05_DNS_RATE_ANOMALY", "rule_name": "DNS Query Flood / High Query Rate", "severity": "HIGH",
                    "source_ip": src_ip, "target_ip": grp["dst_ip"].mode()[0] if not grp.empty else "DNS Server",
                    "time_start": round(float(grp["relative_time"].min()), 2), "time_end": round(float(grp["relative_time"].max()), 2),
                    "evidence": f"{cnt} DNS queries in {round(dur, 2)}s ({rate} queries/s, threshold: {max_rate}).",
                    "reason": "Host generated DNS queries at a suspicious velocity.",
                    "false_positive": "Aggressive web browser pre-fetching or local DNS cache failure.",
                    "mitigation": "Enforce DNS query rate limiting and inspect domain queries for beaconing patterns."
                })

        r = dns_df[dns_df["dns_is_response"] & (dns_df["dns_rcode"] == "NXDOMAIN")]
        for dst_ip, grp in r.groupby("dst_ip"):
            if dst_ip == "Unknown" or len(grp) < nx_th: continue
            sample_d = ", ".join(grp["dns_query"].dropna().unique()[:5])
            alerts.append({
                "rule_id": "RULE_05_DNS_NXDOMAIN_SURGE", "rule_name": "DNS NXDOMAIN Anomaly (Failed Domain Lookups)", "severity": "HIGH",
                "source_ip": dst_ip, "target_ip": grp["src_ip"].mode()[0] if not grp.empty else "DNS Server",
                "time_start": round(float(grp["relative_time"].min()), 2), "time_end": round(float(grp["relative_time"].max()), 2),
                "evidence": f"{len(grp)} NXDOMAIN responses received (threshold: {nx_th}). Sample: [{sample_d}].",
                "reason": "High frequency of failed domain name resolutions, characteristic of malware DGA domains.",
                "false_positive": "Misconfigured applications or typosquatting errors.",
                "mitigation": "Audit client system for background malware processes and check domain lists."
            })
        return alerts

    def _detect_high_retransmissions(self, df):
        tcp_df = df[df["tcp_seq"].notna() & df["src_port"].notna() & df["dst_port"].notna() & (df["src_ip"] != "Unknown")]
        if tcp_df.empty: return []
        th_pct, min_pkts = self.th["retransmission_threshold_pct"], self.th["retransmission_min_packets"]
        alerts = []
        for (src_ip, dst_ip, sport, dport), grp in tcp_df.groupby(["src_ip", "dst_ip", "src_port", "dst_port"]):
            if len(grp) < min_pkts: continue
            seqs = grp[(grp["length"] > 54) | grp["tcp_flags"].str.contains("SYN", na=False)]
            if len(seqs) < min_pkts: continue
            retx = int(seqs.duplicated(subset=["tcp_seq"], keep="first").sum())
            rate = (retx / len(seqs)) * 100
            if rate >= th_pct and retx >= 3:
                alerts.append({
                    "rule_id": "RULE_06_HIGH_RETRANSMISSIONS", "rule_name": "High TCP Retransmission Rate", "severity": "LOW",
                    "source_ip": src_ip, "target_ip": dst_ip,
                    "time_start": round(float(grp["relative_time"].min()), 2), "time_end": round(float(grp["relative_time"].max()), 2),
                    "evidence": f"{retx} retransmitted packets out of {len(seqs)} ({round(rate, 1)}% retransmissions, threshold: {th_pct}%).",
                    "reason": "Retransmission ratio exceeds allowable threshold, indicating packet drops or link congestion.",
                    "false_positive": "Congested Wi-Fi or satellite links, route flapping.",
                    "mitigation": "Inspect physical layer metrics, Wi-Fi signal, and buffer configurations."
                })
        return alerts


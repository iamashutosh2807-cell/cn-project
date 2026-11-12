import os, json, time
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core import (
    parse_pcap_source, get_packet_details,
    compute_summary_metrics, compute_protocol_distribution,
    compute_top_talkers, compute_traffic_timeline,
    compute_tcp_statistics, compute_dns_statistics,
    AnomalyDetector, DEFAULT_THRESHOLDS,
    LiveCaptureSession, ensure_all_sample_pcaps, generate_pdf_report
)

st.set_page_config(page_title="Network Traffic Analyzer & Anomaly Detection", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    .metric-card { background-color: #f8f9fb; border-radius: 8px; padding: 14px; border: 1px solid #e2e8f0; text-align: center; }
    .metric-val { font-size: 24px; font-weight: 700; color: #1e3a8a; }
    .metric-label { font-size: 12px; color: #64748b; text-transform: uppercase; }
    .alert-card { padding: 10px 14px; border-radius: 4px; margin-bottom: 10px; }
    .alert-high { background: #fef2f2; border-left: 5px solid #ef4444; }
    .alert-med { background: #fffbeb; border-left: 5px solid #f59e0b; }
    .alert-low { background: #f0fdf4; border-left: 5px solid #10b981; }
</style>
""", unsafe_allow_html=True)

for k, v in [("live_session", LiveCaptureSession()), ("last_parsed_source", None), ("df", pd.DataFrame()), ("raw_pkts", [])]:
    if k not in st.session_state: st.session_state[k] = v

samples = ensure_all_sample_pcaps()

st.sidebar.title("🛡️ Traffic Analyzer")
st.sidebar.caption("Computer Networks PBL Project | JIIT Noida")

input_mode = st.sidebar.radio("Data Source Mode", ["📁 Pre-bundled Sample PCAPs", "📤 Upload Custom PCAP", "📡 Live Packet Capture"], index=0)
active_source = None

if input_mode == "📁 Pre-bundled Sample PCAPs":
    sample_choice = st.sidebar.selectbox("Choose Sample Scenario:", list(samples.keys()), index=0)
    active_source = samples[sample_choice]
    st.sidebar.info(f"Loaded: `{os.path.basename(active_source)}`")
elif input_mode == "📤 Upload Custom PCAP":
    f = st.sidebar.file_uploader("Upload .pcap or .pcapng", type=["pcap", "pcapng"])
    if f: active_source = f
elif input_mode == "📡 Live Packet Capture":
    st.sidebar.subheader("Live Sniffer Settings")
    iface = st.sidebar.selectbox("Interface:", LiveCaptureSession.get_available_interfaces())
    bpf = st.sidebar.text_input("BPF Filter (e.g. tcp, udp, port 80):", "")
    limit = st.sidebar.number_input("Packet Limit (0 for continuous):", 0, 5000, 100, 25)

    c1, c2 = st.sidebar.columns(2)
    session = st.session_state.live_session
    stat = session.get_status()

    with c1:
        if st.button("▶️ Start", disabled=stat["is_capturing"], use_container_width=True):
            session.start(iface=iface, bpf_filter=bpf, count=limit)
            st.rerun()
    with c2:
        if st.button("⏹️ Stop", disabled=not stat["is_capturing"], use_container_width=True):
            session.stop()
            st.rerun()

    if stat["is_capturing"]:
        st.sidebar.warning(f"Capturing... Packets: {stat['packet_count']} ({stat['duration']}s)")
        time.sleep(0.5)
        st.rerun()
    elif stat["packet_count"] > 0:
        st.sidebar.success(f"Captured {stat['packet_count']} packets.")
        if st.sidebar.button("Load Captured Packets"): active_source = session.get_packets()
    if stat["error"]: st.sidebar.error(f"Capture error: {stat['error']}")

with st.sidebar.expander("⚙️ Tunable Anomaly Rules", expanded=False):
    st.caption("Adjust detection sensitivities:")
    th_ps_ports = st.slider("Port Scan Min Ports:", 5, 50, DEFAULT_THRESHOLDS["port_scan_min_ports"])
    th_ps_win = st.slider("Port Scan Window (sec):", 2, 30, int(DEFAULT_THRESHOLDS["port_scan_window_sec"]))
    th_syn_min = st.slider("SYN Flood Min Packets:", 5, 50, DEFAULT_THRESHOLDS["syn_flood_min_syns"])
    th_spike_mult = st.slider("Traffic Spike Multiplier:", 1.5, 6.0, float(DEFAULT_THRESHOLDS["traffic_spike_multiplier"]), 0.5)
    th_icmp_min = st.slider("ICMP Flood Min Packets:", 10, 60, DEFAULT_THRESHOLDS["icmp_flood_min_packets"])
    th_dns_rate = st.slider("DNS Query Max Rate (pps):", 5, 50, int(DEFAULT_THRESHOLDS["dns_query_rate_pps"]))
    th_dns_nx = st.slider("DNS NXDOMAIN Threshold:", 2, 20, DEFAULT_THRESHOLDS["dns_nxdomain_threshold"])
    th_retx_pct = st.slider("TCP Retransmission %:", 5, 40, int(DEFAULT_THRESHOLDS["retransmission_threshold_pct"]))

custom_thresholds = {
    "port_scan_min_ports": th_ps_ports, "port_scan_window_sec": float(th_ps_win),
    "syn_flood_min_syns": th_syn_min, "traffic_spike_multiplier": th_spike_mult,
    "icmp_flood_min_packets": th_icmp_min, "dns_query_rate_pps": float(th_dns_rate),
    "dns_nxdomain_threshold": th_dns_nx, "retransmission_threshold_pct": float(th_retx_pct)
}

if active_source is not None and (st.session_state.last_parsed_source != active_source or st.session_state.df.empty):
    with st.spinner("Parsing packets and extracting protocol layers..."):
        df, raw_pkts = parse_pcap_source(active_source)
        st.session_state.df, st.session_state.raw_pkts, st.session_state.last_parsed_source = df, raw_pkts, active_source

df = st.session_state.df
raw_pkts = st.session_state.raw_pkts

st.title("🛡️ Network Traffic Analyzer and Anomaly Detection System")
st.markdown("""
**B.Tech CSE III-Year V Semester (2026-27) | Computer Networks Project**  
*Submitted by:* **Ashutosh Das** (992401030215), **Dipanshu Thakur** (992401030216), **Prashant Tripathi** (992401030222)  
*Submitted to:* **Prof. Madhav Bansal**, Department of Computer Science & Engineering, JIIT Noida
""")

if df.empty:
    st.info("👈 Please select a sample PCAP from the sidebar or upload a capture file to begin.")
    st.stop()

with st.expander("🔍 Filter Active Traffic View", expanded=False):
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        protos = sorted(df["protocol"].unique().tolist())
        sel_protos = st.multiselect("Protocols:", protos, default=protos)
    with f2: ip_q = st.text_input("Search IP Address:", "").strip()
    with f3: port_q = st.text_input("Port (e.g. 80, 443, 53):", "").strip()
    with f4:
        min_t, max_t = float(df["relative_time"].min()), float(df["relative_time"].max())
        t_range = st.slider("Time Window (sec):", min_t, max_t, (min_t, max_t)) if max_t > min_t else (min_t, max_t)

filtered_df = df.copy()
if sel_protos: filtered_df = filtered_df[filtered_df["protocol"].isin(sel_protos)]
if ip_q: filtered_df = filtered_df[filtered_df["src_ip"].str.contains(ip_q, na=False) | filtered_df["dst_ip"].str.contains(ip_q, na=False)]
if port_q.isdigit():
    p_num = int(port_q)
    filtered_df = filtered_df[(filtered_df["src_port"] == p_num) | (filtered_df["dst_port"] == p_num)]
if t_range[1] > t_range[0]:
    filtered_df = filtered_df[(filtered_df["relative_time"] >= t_range[0]) & (filtered_df["relative_time"] <= t_range[1])]
if filtered_df.empty:
    st.warning("No packets match the filter criteria. Showing all packets.")
    filtered_df = df

metrics = compute_summary_metrics(filtered_df)
protocol_df = compute_protocol_distribution(filtered_df)
top_src, top_dst, top_flows = compute_top_talkers(filtered_df)
timeline_df = compute_traffic_timeline(filtered_df, interval_sec=1.0)
tcp_stats = compute_tcp_statistics(filtered_df)
dns_stats = compute_dns_statistics(filtered_df)
alerts = AnomalyDetector(custom_thresholds).detect_all(filtered_df)

tab_overview, tab_proto, tab_hosts, tab_tcp_dns, tab_anomalies, tab_inspector, tab_export = st.tabs([
    "📊 Overview & Metrics", "🌐 Protocol Analysis", "👥 Hosts & Flows",
    "🔌 TCP & DNS Deep Dive", f"🚨 Anomaly Detection ({len(alerts)})",
    "🔍 Packet Inspector", "📄 Export & Academic Report"
])

with tab_overview:
    kpi_cols = st.columns(6)
    v_str = f"{round(metrics['total_bytes']/1024, 1)} KB" if metrics['total_bytes'] < 1048576 else f"{round(metrics['total_bytes']/1048576, 2)} MB"
    kpis = [
        ("Total Packets", f"{metrics['total_packets']:,}"), ("Total Volume", v_str),
        ("Duration", f"{metrics['duration_sec']}s"), ("Avg Rate", f"{metrics['avg_packet_rate']}/s"),
        ("Active Hosts", f"{metrics['unique_src_ips']} Src / {metrics['unique_dst_ips']} Dst"),
        ("Anomaly Alerts", f"{len(alerts)}")
    ]
    for col, (l, v) in zip(kpi_cols, kpis):
        clr = "#dc2626" if l == "Anomaly Alerts" and len(alerts) > 0 else "#1e3a8a"
        col.markdown(f'<div class="metric-card"><div class="metric-label">{l}</div><div class="metric-val" style="color:{clr};">{v}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Protocol Distribution (Packet Count)")
        fig_pie = px.pie(protocol_df, names="protocol", values="packets", hole=0.45, color_discrete_sequence=px.colors.qualitative.Safe)
        fig_pie.update_traces(textposition='inside', textinfo='percent+label')
        fig_pie.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
        st.plotly_chart(fig_pie, use_container_width=True)
    with c2:
        st.subheader("Data Volume by Protocol (Bytes)")
        fig_bar = px.bar(protocol_df, x="protocol", y="bytes", color="protocol", text_auto=True, color_discrete_sequence=px.colors.qualitative.Safe)
        fig_bar.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300, showlegend=False)
        st.plotly_chart(fig_bar, use_container_width=True)

    st.subheader("📈 Traffic Throughput Over Time")
    if not timeline_df.empty:
        ft = go.Figure()
        ft.add_trace(go.Scatter(x=timeline_df["time_bucket"], y=timeline_df["packets"], mode="lines+markers", name="Packets / sec", line=dict(color="#2563eb", width=2), fill="tozeroy"))
        ft.add_trace(go.Scatter(x=timeline_df["time_bucket"], y=timeline_df["kbps"], mode="lines", name="Bandwidth (Kbps)", yaxis="y2", line=dict(color="#10b981", width=2, dash="dot")))
        ft.update_layout(yaxis=dict(title="Packets / sec"), yaxis2=dict(title="Throughput (Kbps)", overlaying="y", side="right"), xaxis=dict(title="Relative Time (seconds)"), margin=dict(t=20, b=20, l=40, r=40), height=320, hovermode="x unified")
        st.plotly_chart(ft, use_container_width=True)

with tab_proto:
    st.subheader("Protocol Breakdown Table")
    st.dataframe(protocol_df.style.format({"packets": "{:,}", "bytes": "{:,}", "pct_packets": "{:.2f}%", "pct_bytes": "{:.2f}%"}), use_container_width=True)
    st.markdown("<br>", unsafe_allow_html=True)
    p1, p2 = st.columns(2)
    with p1:
        st.subheader("Packet Size Distribution (Histogram)")
        fh = px.histogram(filtered_df, x="length", nbins=35, color="protocol", marginal="box", color_discrete_sequence=px.colors.qualitative.Plotly)
        fh.update_layout(xaxis_title="Packet Length (bytes)", yaxis_title="Count", margin=dict(t=20, b=20, l=20, r=20), height=340)
        st.plotly_chart(fh, use_container_width=True)
    with p2:
        st.subheader("Packet Size Statistics Summary")
        st.table(pd.DataFrame({
            "Metric": ["Average Size", "Median Size", "Standard Deviation", "Minimum Size", "Maximum Size"],
            "Value": [f"{metrics['avg_packet_size']} bytes", f"{filtered_df['length'].median():.1f} bytes", f"{metrics['std_packet_size']} bytes", f"{metrics['min_packet_size']} bytes", f"{metrics['max_packet_size']} bytes"]
        }))
        st.caption("ℹ️ *Network Concept:* Small packets (<100B) represent TCP ACKs/SYNs or ICMP echoes; larger packets (~1500B) match the MTU carrying data.")

with tab_hosts:
    st.subheader("Top Communicating Hosts & Network Flows")
    h1, h2 = st.columns(2)
    with h1:
        st.markdown("**Top 10 Source IPs**")
        if not top_src.empty:
            fs = px.bar(top_src, x="packets", y="src_ip", orientation="h", text="packets", color="packets", color_continuous_scale="Blues")
            fs.update_layout(yaxis=dict(autorange="reversed"), height=300, margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fs, use_container_width=True)
    with h2:
        st.markdown("**Top 10 Destination IPs**")
        if not top_dst.empty:
            fd = px.bar(top_dst, x="packets", y="dst_ip", orientation="h", text="packets", color="packets", color_continuous_scale="Oranges")
            fd.update_layout(yaxis=dict(autorange="reversed"), height=300, margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fd, use_container_width=True)
    st.markdown("---")
    st.subheader("Top IP Conversation Matrix (Flows)")
    if not top_flows.empty: st.dataframe(top_flows, use_container_width=True, hide_index=True)

with tab_tcp_dns:
    ts, ds = st.tabs(["🔌 TCP Handshake & Connection Analysis", "🔎 DNS Queries & Resolution"])
    with ts:
        t1, t2, t3, t4 = st.columns(4)
        t1.metric("Total TCP Packets", tcp_stats["total_tcp_packets"])
        t2.metric("Handshakes Established", tcp_stats["handshake_stats"]["established"])
        t3.metric("Incomplete Handshakes", tcp_stats["handshake_stats"]["incomplete"])
        t4.metric("Retransmissions", f"{tcp_stats['retransmission_count']} ({tcp_stats['retransmission_rate_pct']}%)")

        col_f1, col_f2 = st.columns(2)
        with col_f1:
            st.markdown("**TCP Flags Distribution**")
            f_df = pd.DataFrame(list(tcp_stats["flag_counts"].items()), columns=["Flag", "Count"])
            st.plotly_chart(px.bar(f_df, x="Flag", y="Count", color="Flag", text_auto=True).update_layout(height=280, margin=dict(t=10, b=10, l=10, r=10), showlegend=False), use_container_width=True)
        with col_f2:
            st.markdown("**TCP Connection States**")
            if not tcp_stats["connections"].empty:
                sc = tcp_stats["connections"]["state"].value_counts().reset_index()
                sc.columns = ["State", "Count"]
                st.plotly_chart(px.pie(sc, names="State", values="Count", hole=0.4).update_layout(height=280, margin=dict(t=10, b=10, l=10, r=10)), use_container_width=True)
        if not tcp_stats["connections"].empty:
            st.dataframe(tcp_stats["connections"].head(15), use_container_width=True, hide_index=True)

    with ds:
        d1, d2, d3 = st.columns(3)
        d1.metric("Total DNS Packets", dns_stats["total_dns_packets"])
        d2.metric("DNS Queries", dns_stats["total_queries"])
        d3.metric("DNS Responses", dns_stats["total_responses"])

        cd1, cd2 = st.columns(2)
        with cd1:
            st.markdown("**Top Queried Domains**")
            st.dataframe(dns_stats["top_domains"], use_container_width=True, hide_index=True) if not dns_stats["top_domains"].empty else st.info("No DNS queries observed.")
        with cd2:
            st.markdown("**DNS Response Codes**")
            if not dns_stats["response_codes"].empty:
                st.plotly_chart(px.bar(dns_stats["response_codes"], x="rcode", y="count", color="rcode", text_auto=True).update_layout(height=250, margin=dict(t=10, b=10, l=10, r=10), showlegend=False), use_container_width=True)
            else: st.info("No DNS response codes observed.")
        if not dns_stats["failed_queries"].empty:
            st.warning(f"⚠️ {len(dns_stats['failed_queries'])} Failed Domain Resolutions:")
            st.dataframe(dns_stats["failed_queries"], use_container_width=True, hide_index=True)

with tab_anomalies:
    st.subheader("🛡️ Rule-Based Anomaly Detection & Threat Explanation")
    sev_c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        if a["severity"] in sev_c: sev_c[a["severity"]] += 1

    a1, a2, a3, a4 = st.columns(4)
    a1.metric("🚨 High Severity", sev_c["HIGH"] + sev_c["CRITICAL"])
    a2.metric("⚠️ Medium Severity", sev_c["MEDIUM"])
    a3.metric("ℹ️ Low Severity", sev_c["LOW"])
    a4.metric("Total Flags", len(alerts))
    st.markdown("---")

    if not alerts:
        st.success("✅ **Clean Traffic:** No suspicious patterns or anomaly thresholds triggered.")
    else:
        for idx, alert in enumerate(alerts, 1):
            sev = alert["severity"]
            cls = "alert-high" if sev in ("CRITICAL", "HIGH") else "alert-med" if sev == "MEDIUM" else "alert-low"
            with st.expander(f"[{sev}] Alert #{idx}: {alert['rule_name']} ({alert['source_ip']} ➔ {alert['target_ip']})", expanded=(idx <= 2)):
                st.markdown(f'<div class="alert-card {cls}"><b>Rule ID:</b> <code>{alert["rule_id"]}</code> | <b>Time Window:</b> {alert["time_start"]}s to {alert["time_end"]}s</div>', unsafe_allow_html=True)
                ca1, ca2 = st.columns(2)
                with ca1:
                    st.markdown(f"**🔍 Concrete Evidence:**\n{alert['evidence']}")
                    st.markdown(f"**🧠 Detection Logic:**\n{alert['reason']}")
                with ca2:
                    st.markdown(f"**⚠️ Possible False Positive:**\n{alert['false_positive']}")
                    st.markdown(f"**🛡️ Recommended Mitigation:**\n{alert['mitigation']}")

with tab_inspector:
    st.subheader("🔍 Wireshark-Style Packet Inspector")
    st.dataframe(filtered_df[["packet_num", "relative_time", "src_ip", "dst_ip", "protocol", "length", "tcp_flags", "info"]].head(300), use_container_width=True, hide_index=True)
    st.markdown("---")
    st.markdown("### Deep Packet Decode & Hex Dump")
    sel = st.number_input("Enter Packet Number to Decode:", 1, len(raw_pkts), 1, 1)
    if 1 <= sel <= len(raw_pkts):
        details = get_packet_details(raw_pkts[sel - 1])
        i1, i2 = st.columns(2)
        with i1:
            st.markdown(f"**Packet #{sel} Summary:** `{details['summary']}`")
            for l in details["layers"]:
                with st.expander(f"Layer: {l['layer']}", expanded=True): st.json(l["fields"])
        with i2:
            st.markdown("**Hexadecimal & ASCII Packet Payload:**")
            st.code(details["hex_dump"], language="text")

with tab_export:
    st.subheader("📄 Export Artifacts & Academic Documentation")
    e1, e2, e3 = st.columns(3)
    with e1:
        st.markdown("#### 1. Academic PDF Report")
        if st.button("Generate & Download PDF", type="primary", use_container_width=True):
            with st.spinner("Generating PDF..."):
                pdf_b = generate_pdf_report(metrics, protocol_df, top_src, top_dst, alerts, filename_or_buffer=False)
                st.download_button("📥 Click to Download PDF", pdf_b, "JIIT_Network_Traffic_Analysis_Report.pdf", "application/pdf", use_container_width=True)
    with e2:
        st.markdown("#### 2. Parsed Data (CSV)")
        st.download_button("📥 Download CSV", filtered_df.to_csv(index=False).encode('utf-8'), "traffic_packets.csv", "text/csv", use_container_width=True)
    with e3:
        st.markdown("#### 3. Alerts Log (JSON)")
        st.download_button("📥 Download JSON", json.dumps(alerts, indent=2).encode('utf-8'), "anomaly_alerts.json", "application/json", use_container_width=True)

    st.markdown("---")
    st.markdown("""
    ### 🎓 Academic Project Summary
    - **Course:** Computer Networks (B.Tech CSE III-Year V Semester 2026-27)
    - **Institute:** Jaypee Institute of Information Technology (JIIT), Sector 62, Noida
    - **Project Title:** Network Traffic Analyzer and Anomaly Detection System
    - **Team:** Ashutosh Das (992401030215), Dipanshu Thakur (992401030216), Prashant Tripathi (992401030222)
    - **Faculty Guide:** Prof. Madhav Bansal
    """)

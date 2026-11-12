from fpdf import FPDF
from datetime import datetime


class TrafficReportPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "JIIT Noida - Computer Networks PBL | Network Traffic Analyzer & Anomaly Detection", border=False, align="L")
        self.set_font("Helvetica", "I", 9)
        self.cell(0, 6, datetime.now().strftime("%Y-%m-%d %H:%M"), border=False, align="R")
        self.ln(8)
        self.set_draw_color(200, 200, 200)
        self.line(10, 15, 200, 15)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Dept. of CSE, Jaypee Institute of Information Technology", align="C")


def generate_pdf_report(summary_metrics, protocol_df, top_src_df, top_dst_df, alerts, filename_or_buffer="network_traffic_report.pdf"):
    pdf = TrafficReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    pdf.set_fill_color(24, 43, 73)
    pdf.rect(10, 20, 190, 24, "F")
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(12, 23)
    pdf.cell(186, 9, "Network Traffic Analysis & Anomaly Detection Report", align="C")
    pdf.ln(7)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(220, 230, 242)
    pdf.cell(186, 6, "B.Tech CSE III-Year V Semester | JIIT Noida", align="C")
    pdf.ln(12)

    pdf.set_xy(10, 48)
    pdf.set_fill_color(245, 247, 250)
    pdf.set_draw_color(210, 220, 235)
    pdf.rect(10, 48, 190, 24, "DF")

    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_xy(14, 51)
    pdf.cell(85, 5, "Submitted by:", border=False)
    pdf.cell(85, 5, "Submitted to:", border=False)
    pdf.ln(5)

    pdf.set_font("Helvetica", "", 8.5)
    for text_left, text_right in [
        ("1. Ashutosh Das (992401030215)", "Prof. Madhav Bansal"),
        ("2. Dipanshu Thakur (992401030216)", "Department of Computer Science & Engineering"),
        ("3. Prashant Tripathi (992401030222)", "")
    ]:
        pdf.set_x(14)
        pdf.cell(85, 4, text_left, border=False)
        pdf.cell(85, 4, text_right, border=False)
        pdf.ln(4)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 8, "1. Executive Summary & Key Traffic Metrics")
    pdf.ln(8)
    pdf.set_draw_color(24, 43, 73)
    pdf.line(10, pdf.get_y(), 80, pdf.get_y())
    pdf.ln(3)

    metrics_data = [
        ("Total Packets Analyzed", f"{summary_metrics.get('total_packets', 0):,}"),
        ("Total Data Volume", f"{round(summary_metrics.get('total_bytes', 0) / 1024, 2):,} KB ({summary_metrics.get('total_bytes', 0):,} bytes)"),
        ("Capture Duration", f"{summary_metrics.get('duration_sec', 0.0)} seconds"),
        ("Average Packet Rate", f"{summary_metrics.get('avg_packet_rate', 0.0)} packets/sec"),
        ("Average Throughput", f"{summary_metrics.get('avg_byte_rate_kbps', 0.0)} Kbps"),
        ("Average Packet Size", f"{summary_metrics.get('avg_packet_size', 0.0)} bytes (Min: {summary_metrics.get('min_packet_size', 0)}, Max: {summary_metrics.get('max_packet_size', 0)})"),
        ("Unique Communicating Hosts", f"Source IPs: {summary_metrics.get('unique_src_ips', 0)} | Destination IPs: {summary_metrics.get('unique_dst_ips', 0)}"),
        ("Distinct Protocols", f"{summary_metrics.get('unique_protocols', 0)} protocols identified"),
        ("Total Anomaly Alerts", f"{len(alerts)} suspicious pattern(s) flagged")
    ]

    for label, val in metrics_data:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(50, 50, 50)
        pdf.set_fill_color(240, 243, 246)
        pdf.cell(65, 5.5, f"  {label}:", border=1, fill=True)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(125, 5.5, f"  {val}", border=1)
        pdf.ln(5.5)
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 8, "2. Protocol Distribution & Volume")
    pdf.ln(8)
    pdf.line(10, pdf.get_y(), 80, pdf.get_y())
    pdf.ln(3)

    if not protocol_df.empty:
        pdf.set_fill_color(36, 75, 125)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8.5)
        for h, w in [(" Protocol", 45), (" Packet Count", 35), (" % Packets", 35), (" Total Bytes", 40), (" % Bytes", 35)]:
            pdf.cell(w, 6, h, border=1, fill=True, align="R" if "%" in h or "Count" in h or "Bytes" in h else "L")
        pdf.ln(6)

        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 8)
        for _, row in protocol_df.iterrows():
            pdf.cell(45, 5.5, f" {row['protocol']}", border=1)
            pdf.cell(35, 5.5, f"{int(row['packets']):,} ", border=1, align="R")
            pdf.cell(35, 5.5, f"{row['pct_packets']}% ", border=1, align="R")
            pdf.cell(40, 5.5, f"{int(row['bytes']):,} ", border=1, align="R")
            pdf.cell(35, 5.5, f"{row['pct_bytes']}% ", border=1, align="R")
            pdf.ln(5.5)
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 8, "3. Top Communicating Hosts (Top Talkers)")
    pdf.ln(8)
    pdf.line(10, pdf.get_y(), 80, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_fill_color(230, 235, 245)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(92, 6, " Top Source IPs", border=1, fill=True)
    pdf.cell(6, 6, "", border=False)
    pdf.cell(92, 6, " Top Destination IPs", border=1, fill=True)
    pdf.ln(6)

    pdf.set_font("Helvetica", "", 8)
    for i in range(min(5, max(len(top_src_df), len(top_dst_df)))):
        src_s = f" {top_src_df.iloc[i]['src_ip']} ({int(top_src_df.iloc[i]['packets'])} pkts)" if i < len(top_src_df) else " -"
        dst_s = f" {top_dst_df.iloc[i]['dst_ip']} ({int(top_dst_df.iloc[i]['packets'])} pkts)" if i < len(top_dst_df) else " -"
        pdf.cell(92, 5, src_s, border=1)
        pdf.cell(6, 5, "", border=False)
        pdf.cell(92, 5, dst_s, border=1)
        pdf.ln(5)

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(160, 25, 25)
    pdf.cell(0, 8, "4. Rule-Based Anomaly Detection & Security Alerts")
    pdf.ln(8)
    pdf.set_draw_color(160, 25, 25)
    pdf.line(10, pdf.get_y(), 105, pdf.get_y())
    pdf.ln(3)

    if alerts:
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(190, 4.5, "Each rule inspects packet headers and flow behavior in time windows. Flagged patterns represent indicators of abnormal activity.")
        pdf.ln(3)

        for idx, alert in enumerate(alerts, 1):
            if pdf.get_y() > 215:
                pdf.add_page()
            sev = alert["severity"]
            sev_color = (190, 30, 30) if sev in ("CRITICAL", "HIGH") else (200, 120, 0) if sev == "MEDIUM" else (60, 110, 170)
            start_y = pdf.get_y()

            pdf.set_xy(12, start_y + 1.5)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*sev_color)
            pdf.cell(120, 5, f"[{sev}] Alert #{idx}: {alert['rule_name']}", border=False)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(66, 5, f"Window: {alert['time_start']}s - {alert['time_end']}s", border=False, align="R")
            pdf.ln(5)

            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(40, 40, 40)
            pdf.set_x(12)
            pdf.cell(20, 4, "Host Pair:", border=False)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(166, 4, f"{alert['source_ip']} -> {alert['target_ip']}", border=False)
            pdf.ln(4)

            for title, key in [("Evidence:", "evidence"), ("Detection:", "reason"), ("False Pos:", "false_positive")]:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(140, 70, 0) if title.startswith("False") else pdf.set_text_color(40, 40, 40)
                pdf.set_x(12)
                pdf.cell(20, 4, title, border=False)
                pdf.set_font("Helvetica", "I" if title.startswith("False") else "", 8)
                pdf.multi_cell(166, 4, alert[key])

            card_h = pdf.get_y() - start_y + 2
            pdf.set_fill_color(248, 249, 251)
            pdf.set_draw_color(200, 205, 215)
            pdf.rect(10, start_y, 190, card_h, "D")
            pdf.ln(4)
    else:
        pdf.set_fill_color(240, 250, 240)
        pdf.set_draw_color(180, 220, 180)
        pdf.rect(10, pdf.get_y(), 190, 14, "DF")
        pdf.set_xy(14, pdf.get_y() + 4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(30, 130, 50)
        pdf.cell(180, 6, "Clean Traffic: No suspicious anomaly patterns triggered current threshold rules.", align="C")
        pdf.ln(16)

    if pdf.get_y() > 220:
        pdf.add_page()
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(0, 8, "5. False Positives, Limitations & Conclusion")
    pdf.ln(8)
    pdf.line(10, pdf.get_y(), 95, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    for c in [
        "1. Threshold Tuning: Fixed thresholds can yield false alarms during high-bandwidth legitimate streaming, OS updates, or scheduled backups.",
        "2. Encrypted Payloads (TLS/HTTPS): Payload contents are opaque, requiring traffic analysis to rely primarily on layer-3/layer-4 headers, flow rates, and connection states.",
        "3. Live Capture Privileges: Real-time sniffing requires administrative rights (Npcap on Windows / root on Linux) and interface binding.",
        "4. Conclusion: The rule-based analyzer successfully surfaces high-level protocol distributions and explainable indicators of suspicious network behavior, providing clear practical reinforcement of TCP/IP networking principles."
    ]:
        pdf.multi_cell(190, 4.5, c)
        pdf.ln(1.5)

    if isinstance(filename_or_buffer, str):
        pdf.output(filename_or_buffer)
        return filename_or_buffer
    return bytes(pdf.output())

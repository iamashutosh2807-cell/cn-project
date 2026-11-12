import os, unittest
from core import (
    parse_pcap_source, get_packet_details,
    compute_summary_metrics, compute_protocol_distribution,
    compute_top_talkers, compute_traffic_timeline,
    compute_tcp_statistics, compute_dns_statistics,
    AnomalyDetector, ensure_all_sample_pcaps, generate_pdf_report
)

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_pcaps")


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples = ensure_all_sample_pcaps()
        cls.detector = AnomalyDetector()

    def test_parser_normal_traffic(self):
        df, raw_pkts = parse_pcap_source(os.path.join(SAMPLE_DIR, "normal_traffic.pcap"))
        self.assertFalse(df.empty)
        self.assertGreater(len(df), 5)
        self.assertTrue(set(["HTTP", "DNS", "ICMP"]).issubset(set(df["protocol"].unique())))
        details = get_packet_details(raw_pkts[0])
        self.assertTrue(all(k in details for k in ("summary", "layers", "hex_dump")))

    def test_analyzer_metrics(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "normal_traffic.pcap"))
        m = compute_summary_metrics(df)
        self.assertTrue(m["total_packets"] > 0 and m["total_bytes"] > 0 and m["avg_packet_rate"] > 0)
        self.assertFalse(compute_protocol_distribution(df).empty)
        top_src, top_dst, _ = compute_top_talkers(df)
        self.assertFalse(top_src.empty)
        self.assertFalse(compute_traffic_timeline(df, 1.0).empty)
        self.assertGreater(compute_tcp_statistics(df)["total_tcp_packets"], 0)
        self.assertGreater(compute_dns_statistics(df)["total_dns_packets"], 0)

    def test_detector_port_scan(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "port_scan.pcap"))
        alerts = self.detector.detect_all(df)
        ps_alerts = [a for a in alerts if a["rule_id"] == "RULE_01_PORT_SCAN"]
        self.assertTrue(len(ps_alerts) > 0)
        self.assertEqual(ps_alerts[0]["severity"], "HIGH")
        self.assertEqual(ps_alerts[0]["source_ip"], "192.168.1.189")

    def test_detector_syn_flood(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "syn_flood.pcap"))
        alerts = self.detector.detect_all(df)
        syn_alerts = [a for a in alerts if a["rule_id"] == "RULE_02_SYN_FLOOD"]
        self.assertTrue(len(syn_alerts) > 0)
        self.assertEqual(syn_alerts[0]["source_ip"], "10.0.0.88")

    def test_detector_icmp_flood(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "icmp_flood.pcap"))
        self.assertTrue(any(a["rule_id"] == "RULE_04_ICMP_FLOOD" for a in self.detector.detect_all(df)))

    def test_detector_dns_anomaly(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "dns_anomaly.pcap"))
        self.assertTrue(any(a["rule_id"] == "RULE_05_DNS_NXDOMAIN_SURGE" for a in self.detector.detect_all(df)))

    def test_detector_mixed_scenario_spikes(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "mixed_scenario.pcap"))
        alerts = self.detector.detect_all(df)
        r_ids = {a["rule_id"] for a in alerts}
        self.assertTrue(len(r_ids.intersection({"RULE_01_PORT_SCAN", "RULE_03_TRAFFIC_SPIKE", "RULE_05_DNS_NXDOMAIN_SURGE"})) >= 2)

    def test_pdf_report_generation(self):
        df, _ = parse_pcap_source(os.path.join(SAMPLE_DIR, "mixed_scenario.pcap"))
        test_pdf = os.path.join(SAMPLE_DIR, "test_output_report.pdf")
        generate_pdf_report(compute_summary_metrics(df), compute_protocol_distribution(df),
                            *compute_top_talkers(df)[:2], self.detector.detect_all(df), test_pdf)
        self.assertTrue(os.path.exists(test_pdf) and os.path.getsize(test_pdf) > 1000)
        try: os.remove(test_pdf)
        except Exception: pass


if __name__ == "__main__":
    unittest.main()

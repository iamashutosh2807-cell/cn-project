import os, random
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_pcaps")


def generate_normal_traffic(filename=None):
    random.seed(42)
    filename = filename or os.path.join(SAMPLE_DIR, "normal_traffic.pcap")
    pkts, t = [], 1700000000.0
    cip, dns_ip, web_ip, rtr_ip = "192.168.1.105", "8.8.8.8", "93.184.216.34", "192.168.1.1"

    for pkt, dt in [
        (Ether()/IP(src=cip, dst=dns_ip)/UDP(sport=54321, dport=53)/DNS(id=0x1a2b, qr=0, qd=DNSQR(qname="www.example.com")), 0.035),
        (Ether()/IP(src=dns_ip, dst=cip)/UDP(sport=53, dport=54321)/DNS(id=0x1a2b, qr=1, rcode=0, qd=DNSQR(qname="www.example.com"), an=DNSRR(rrname="www.example.com", rdata=web_ip, ttl=300)), 0.02),
        (Ether()/IP(src=cip, dst=web_ip)/TCP(sport=49152, dport=80, flags="S", seq=1000, ack=0), 0.03),
        (Ether()/IP(src=web_ip, dst=cip)/TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001), 0.01),
        (Ether()/IP(src=cip, dst=web_ip)/TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001), 0.015),
        (Ether()/IP(src=cip, dst=web_ip)/TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001)/Raw(b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n"), 0.04),
        (Ether()/IP(src=web_ip, dst=cip)/TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1055)/Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!"), 0.01),
        (Ether()/IP(src=cip, dst=web_ip)/TCP(sport=49152, dport=80, flags="A", seq=1055, ack=5065), 0.5)
    ]:
        pkt.time = t
        pkts.append(pkt)
        t += dt

    for i in range(4):
        req = Ether()/IP(src=cip, dst=rtr_ip)/ICMP(type=8, code=0, id=101, seq=i+1)
        req.time = t
        pkts.append(req)
        rep = Ether()/IP(src=rtr_ip, dst=cip)/ICMP(type=0, code=0, id=101, seq=i+1)
        rep.time = t + 0.005
        pkts.append(rep)
        t += 1.0

    for ip_a, dom in [("142.250.190.46", "www.google.com"), ("151.101.65.140", "reddit.com")]:
        sp = random.randint(50000, 60000)
        p1 = Ether()/IP(src=cip, dst=dns_ip)/UDP(sport=sp, dport=53)/DNS(id=random.randint(1000, 60000), qr=0, qd=DNSQR(qname=dom))
        p1.time = t
        pkts.append(p1)
        p2 = Ether()/IP(src=dns_ip, dst=cip)/UDP(sport=53, dport=sp)/DNS(id=p1[DNS].id, qr=1, rcode=0, qd=DNSQR(qname=dom), an=DNSRR(rrname=dom, rdata=ip_a, ttl=300))
        p2.time = t + 0.03
        pkts.append(p2)
        s_pkt = Ether()/IP(src=cip, dst=ip_a)/TCP(sport=sp, dport=443, flags="S", seq=2000, ack=0)
        s_pkt.time = t + 0.05
        pkts.append(s_pkt)
        sa_pkt = Ether()/IP(src=ip_a, dst=cip)/TCP(sport=443, dport=sp, flags="SA", seq=7000, ack=2001)
        sa_pkt.time = t + 0.08
        pkts.append(sa_pkt)
        a_pkt = Ether()/IP(src=cip, dst=ip_a)/TCP(sport=sp, dport=443, flags="A", seq=2001, ack=7001)
        a_pkt.time = t + 0.09
        pkts.append(a_pkt)
        t += 0.5

    wrpcap(filename, pkts)
    return filename


def generate_port_scan_traffic(filename=None):
    random.seed(42)
    filename = filename or os.path.join(SAMPLE_DIR, "port_scan.pcap")
    pkts, t = [], 1700000100.0
    atk, tgt = "192.168.1.189", "192.168.1.50"
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]

    for p in ports:
        sp = random.randint(40000, 60000)
        syn = Ether()/IP(src=atk, dst=tgt)/TCP(sport=sp, dport=p, flags="S", seq=random.randint(1000, 50000), ack=0)
        syn.time = t
        pkts.append(syn)
        flg, sq, ak = ("SA", 9999, syn[TCP].seq + 1) if p in (22, 80, 443) else ("RA", 0, syn[TCP].seq + 1)
        resp = Ether()/IP(src=tgt, dst=atk)/TCP(sport=p, dport=sp, flags=flg, seq=sq, ack=ak)
        resp.time = t + 0.005
        pkts.append(resp)
        t += 0.08

    wrpcap(filename, pkts)
    return filename


def generate_syn_flood_traffic(filename=None):
    random.seed(42)
    filename = filename or os.path.join(SAMPLE_DIR, "syn_flood.pcap")
    pkts, t = [], 1700000200.0
    for _ in range(40):
        syn = Ether()/IP(src="10.0.0.88", dst="192.168.1.50")/TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(10000, 999999), ack=0)
        syn.time = t
        pkts.append(syn)
        t += 0.04
    wrpcap(filename, pkts)
    return filename


def generate_icmp_flood_traffic(filename=None):
    random.seed(42)
    filename = filename or os.path.join(SAMPLE_DIR, "icmp_flood.pcap")
    pkts, t = [], 1700000300.0
    for i in range(40):
        req = Ether()/IP(src="192.168.1.77", dst="192.168.1.1")/ICMP(type=8, code=0, id=101, seq=i+1)/Raw(b"ICMP_FLOOD_TEST_DATA")
        req.time = t
        pkts.append(req)
        t += 0.035
    wrpcap(filename, pkts)
    return filename


def generate_dns_anomaly_traffic(filename=None):
    random.seed(42)
    filename = filename or os.path.join(SAMPLE_DIR, "dns_anomaly.pcap")
    pkts, t = [], 1700000400.0
    domains = ["x8f93kd92.biz", "k39fkdmv9.info", "malw8923bot.net", "c2server99a.org",
               "tunneling392.cc", "hiddenxyz123.top", "botnetexfil88.pw", "randpayload39.cn"]
    for d in domains:
        d_id, sp = random.randint(1000, 65000), random.randint(50000, 60000)
        q = Ether()/IP(src="192.168.1.112", dst="192.168.1.1")/UDP(sport=sp, dport=53)/DNS(id=d_id, qr=0, qd=DNSQR(qname=d))
        q.time = t
        pkts.append(q)
        r = Ether()/IP(src="192.168.1.1", dst="192.168.1.112")/UDP(sport=53, dport=sp)/DNS(id=d_id, qr=1, rcode=3, qd=DNSQR(qname=d))
        r.time = t + 0.02
        pkts.append(r)
        t += 0.07
    wrpcap(filename, pkts)
    return filename


def generate_mixed_scenario(filename=None):
    random.seed(42)
    filename = filename or os.path.join(SAMPLE_DIR, "mixed_scenario.pcap")
    pkts, t = [], 1700000500.0
    c, s = "192.168.1.100", "192.168.1.200"

    for i in range(15):
        sp = 40000 + i
        p1 = Ether()/IP(src=c, dst=s)/TCP(sport=sp, dport=80, flags="S", seq=1000*i, ack=0)
        p1.time = t
        pkts.append(p1)
        p2 = Ether()/IP(src=s, dst=c)/TCP(sport=80, dport=sp, flags="SA", seq=5000*i, ack=1000*i+1)
        p2.time = t + 0.02
        pkts.append(p2)
        p3 = Ether()/IP(src=c, dst=s)/TCP(sport=sp, dport=80, flags="A", seq=1000*i+1, ack=5000*i+1)
        p3.time = t + 0.03
        pkts.append(p3)
        t += 0.1

    for p in [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9000]:
        scan = Ether()/IP(src="10.10.14.22", dst=s)/TCP(sport=random.randint(40000, 60000), dport=p, flags="S", seq=12345, ack=0)
        scan.time = t
        pkts.append(scan)
        t += 0.05

    t += 0.5
    for _ in range(45):
        burst = Ether()/IP(src="192.168.1.150", dst=s)/TCP(sport=55555, dport=80, flags="PA", seq=10000, ack=20000)/Raw(b"SPIKE_BURST_PAYLOAD_CHUNK"*40)
        burst.time = t
        pkts.append(burst)
        t += 0.015

    t += 0.5
    for d in ["dga-agent1.com", "dga-agent2.net", "dga-agent3.org", "c2-control-alpha.cc", "unknown-fail.xyz", "sinkhole.top"]:
        d_id = random.randint(1000, 60000)
        q = Ether()/IP(src="192.168.1.180", dst="8.8.8.8")/UDP(sport=53321, dport=53)/DNS(id=d_id, qr=0, qd=DNSQR(qname=d))
        q.time = t
        pkts.append(q)
        r = Ether()/IP(src="8.8.8.8", dst="192.168.1.180")/UDP(sport=53, dport=53321)/DNS(id=d_id, qr=1, rcode=3, qd=DNSQR(qname=d))
        r.time = t + 0.02
        pkts.append(r)
        t += 0.05

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(filename, pkts)
    return filename


def ensure_all_sample_pcaps():
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    files = {
        "Normal Traffic": ("normal_traffic.pcap", generate_normal_traffic),
        "Port Scan Attack": ("port_scan.pcap", generate_port_scan_traffic),
        "TCP SYN Flood": ("syn_flood.pcap", generate_syn_flood_traffic),
        "ICMP Ping Flood": ("icmp_flood.pcap", generate_icmp_flood_traffic),
        "DNS Anomaly (DGA / NXDOMAIN)": ("dns_anomaly.pcap", generate_dns_anomaly_traffic),
        "Mixed Security Scenario": ("mixed_scenario.pcap", generate_mixed_scenario),
    }
    results = {}
    for label, (fname, gen_fn) in files.items():
        fpath = os.path.join(SAMPLE_DIR, fname)
        if not os.path.exists(fpath): gen_fn(fpath)
        results[label] = fpath
    return results

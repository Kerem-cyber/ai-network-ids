import argparse
from collections import Counter, defaultdict, deque

from scapy.all import IP, TCP, PcapReader

parser = argparse.ArgumentParser(description="PCAP üzerinde port taraması kontrolü")
parser.add_argument("pcap")
args = parser.parse_args()

window = 10
threshold = 20
queues = defaultdict(deque)
counts = defaultdict(Counter)
peaks = defaultdict(int)

with PcapReader(args.pcap) as packets:
    for packet in packets:
        if IP not in packet or TCP not in packet:
            continue

        tcp = packet[TCP]
        # Yalnızca bağlantı başlatan SYN paketleri; SYN-ACK yanıtları hariç.
        if not (int(tcp.flags) & 2) or (int(tcp.flags) & 16):
            continue

        key = (packet[IP].src, packet[IP].dst)
        now = float(packet.time)
        port = int(tcp.dport)
        queue = queues[key]
        counter = counts[key]

        while queue and queue[0][0] < now - window:
            _, expired_port = queue.popleft()
            counter[expired_port] -= 1
            if counter[expired_port] == 0:
                del counter[expired_port]

        queue.append((now, port))
        counter[port] += 1
        peaks[key] = max(peaks[key], len(counter))

alerts = 0
for (source, target), peak in peaks.items():
    if peak >= threshold:
        alerts += 1
        print(
            f"TARAMA ŞÜPHESİ | {source} → {target} | "
            f"{window} saniyelik pencerede en fazla {peak} farklı port"
        )

print(f"Kural uyarısı: {alerts}")

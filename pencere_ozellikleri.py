import argparse
from collections import Counter, defaultdict, deque
from pathlib import Path

import pandas as pd
from scapy.all import IP, TCP, PcapReader

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=Path)
args = parser.parse_args()

output = args.pcap.parent / "pencere_ozellikleri.csv"
if output.exists():
    raise SystemExit("Pencere CSV'si zaten mevcut; üzerine yazılmadı.")

queues = defaultdict(deque)
rows = []
previous_time = None

with PcapReader(str(args.pcap)) as packets:
    for packet in packets:
        now = float(packet.time)
        if previous_time is not None and now < previous_time:
            raise SystemExit("Paket zamanları sıralı değil; işlem durduruldu.")
        previous_time = now

        if IP not in packet or TCP not in packet:
            continue
        ip, tcp = packet[IP], packet[TCP]
        flags = int(tcp.flags)
        if not (flags & 2) or (flags & 16):
            continue

        key = (ip.src, ip.dst)
        queue = queues[key]
        while queue and queue[0][0] < now - 10:
            queue.popleft()

        # Aynı portlar ve sıra numarası: yeniden gönderim adayı.
        connection = (int(tcp.sport), int(tcp.dport), int(tcp.seq))
        queue.append((now, connection))

        connections = Counter(item[1] for item in queue)
        ports = {item[1][1] for item in queue}
        rows.append({
            "timestamp": now,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "dst_port": int(tcp.dport),
            "syn_sayisi_10s": len(queue),
            "baglanti_sayisi_10s": len(connections),
            "farkli_port_10s": len(ports),
            "tekrar_syn_10s": len(queue) - len(connections),
        })

if not rows:
    raise SystemExit("Bağlantı başlatan IPv4 TCP SYN paketi bulunamadı.")

data = pd.DataFrame(rows)
with output.open("x", encoding="utf-8", newline="") as handle:
    data.to_csv(handle, index=False)

print(data.groupby(["src_ip", "dst_ip"])[[
    "syn_sayisi_10s", "baglanti_sayisi_10s",
    "farkli_port_10s", "tekrar_syn_10s",
]].max().to_string())
print("Kaydedildi:", output)

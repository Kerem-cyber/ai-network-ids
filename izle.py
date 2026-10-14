import argparse
import subprocess
import sys
import time
from pathlib import Path

import joblib
import pandas as pd

parser = argparse.ArgumentParser(description="Kısa ağ kaydı al ve sınıflandır")
parser.add_argument("--interface", default="eth0")
parser.add_argument("--seconds", type=int, default=30)
args = parser.parse_args()

if not 1 <= args.seconds <= 300:
    parser.error("Süre 1–300 saniye arasında olmalı.")

root = Path(__file__).resolve().parent
bundle = joblib.load(root / "models/gelistirilmis_model.joblib")
mapping = {
    "dst_port": "Destination Port",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "flow_duration": "Flow Duration",
}
if set(bundle["columns"]) != set(mapping.values()):
    raise SystemExit("Model beklenen dört özelliği kullanmıyor.")

folder = root / "kayitlar" / str(time.time_ns())
folder.mkdir(parents=True)
pcap = folder / "trafik.pcap"
csv = folder / "akislar.csv"

print(f"{args.interface}: {args.seconds} saniye kayıt alınıyor…", flush=True)
result = subprocess.run([
    "timeout", "--signal=INT", "--kill-after=5",
    str(args.seconds), "tcpdump", "-i", args.interface,
    "-s", "0", "-w", str(pcap),
])
if result.returncode not in (0, 124):
    raise SystemExit(f"Paket yakalama başarısız: {result.returncode}")

converter = Path(sys.executable).parent / "cicflowmeter"
subprocess.run([
    str(converter), "-f", str(pcap), "-c", str(csv)
], check=True)

try:
    data = pd.read_csv(csv)
except pd.errors.EmptyDataError:
    raise SystemExit("CSV boş; analiz edilecek TCP/UDP akışı oluşmadı.")

missing = [name for name in mapping if name not in data.columns]
if missing:
    raise SystemExit(f"Eksik sütunlar: {missing}")
if data.empty:
    raise SystemExit("Analiz edilecek akış yok.")

features = data[list(mapping)].rename(columns=mapping)
features = features.apply(pd.to_numeric, errors="raise")
features["Flow Duration"] *= 1_000_000
features = features[bundle["columns"]]
if not features.notna().all().all():
    raise SystemExit("Özelliklerde boş değer var; tahmin durduruldu.")
if not ((features >= 0) & (features < float("inf"))).all().all():
    raise SystemExit("Özelliklerde geçersiz değer var; tahmin durduruldu.")

data["Tahmin"] = bundle["pipeline"].predict(features)
data.to_csv(folder / "sonuclar.csv", index=False)

print("\nTahmin özeti:")
print(data["Tahmin"].value_counts().to_string())
for _, row in data[data["Tahmin"] != "BENIGN"].iterrows():
    print(
        f"ŞÜPHELİ: {row['Tahmin']} | "
        f"{row['src_ip']}:{row['src_port']} → "
        f"{row['dst_ip']}:{row['dst_port']}"
    )
print(f"\nKayıtlar: {folder}")

# Port taraması kural kontrolü
print("\nKural tabanlı tarama kontrolü:", flush=True)
rule_result = subprocess.run([
    sys.executable,
    str(root / "tarama_kontrol.py"),
    str(pcap),
], check=True, capture_output=True, text=True)

print(rule_result.stdout, end="")
if rule_result.stderr:
    print(rule_result.stderr, file=sys.stderr, end="")

summary = (
    f"Arayüz: {args.interface}\n"
    f"Kayıt süresi: {args.seconds} saniye\n"
    f"Akış sayısı: {len(data)}\n\n"
    "Model tahminleri:\n"
    + data["Tahmin"].value_counts().to_string()
    + "\n\nKural kontrolü:\n"
    + rule_result.stdout
)
summary_path = folder / "ozet.txt"
summary_path.write_text(summary, encoding="utf-8")
print(f"Özet kaydedildi: {summary_path}")

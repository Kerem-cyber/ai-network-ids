from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

root = Path(__file__).resolve().parent
st.set_page_config(page_title="Ağ Tespit Paneli", layout="wide")
st.title("AI Destekli Ağ Saldırı Tespit Paneli")
st.caption("Kaydedilmiş trafik analizi • Model tahminleri ve tarama kuralı")


# Panelden kayıt başlatma
import socket
import subprocess
import sys

st.subheader("Yeni trafik kaydı")
interfaces = [name for _, name in socket.if_nameindex()]
interface = st.selectbox(
    "Ağ arayüzü",
    interfaces,
    index=interfaces.index("eth0") if "eth0" in interfaces else 0,
)
seconds = st.number_input(
    "Kayıt süresi (saniye)",
    min_value=5,
    max_value=300,
    value=30,
    step=5,
)
st.caption("eth0: ağ trafiği • lo: kendi makinenle yapılan yerel testler")

if st.button("Kayıt başlat", type="primary"):
    with st.spinner("Trafik kaydediliyor ve analiz ediliyor…"):
        result = subprocess.run(
            [
                sys.executable,
                str(root / "izle.py"),
                "--interface", interface,
                "--seconds", str(int(seconds)),
            ],
            cwd=root,
            capture_output=True,
            text=True,
        )
    if result.returncode == 0:
        st.success("Kayıt ve analiz tamamlandı. Yeni kayıt aşağıdaki listede.")
    else:
        st.error("İşlem tamamlanamadı. Aşağıdaki çıktıyı kontrol et.")
    with st.expander("İşlem çıktısı", expanded=result.returncode != 0):
        st.code(result.stdout + "\n" + result.stderr)

if st.button("Kayıt listesini yenile"):
    st.rerun()

records = sorted(
    (root / "kayitlar").glob("*/sonuclar.csv"),
    key=lambda p: p.parent.name,
    reverse=True,
)
if not records:
    st.info("Henüz tamamlanmış kayıt yok. Önce izle.py ile kayıt al.")
    st.stop()

def record_label(path):
    try:
        date = datetime.fromtimestamp(int(path.parent.name) / 1e9)
        return f"{date:%d.%m.%Y %H:%M:%S} — {path.parent.name}"
    except ValueError:
        return path.parent.name

selected = st.selectbox("İncelenecek kayıt", records, format_func=record_label)

try:
    data = pd.read_csv(selected)
except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError) as error:
    st.error(f"Kayıt okunamadı: {error}")
    st.stop()

if "Tahmin" not in data.columns:
    st.error("Bu kayıtta Tahmin sütunu yok.")
    st.stop()

normal = int((data["Tahmin"] == "BENIGN").sum())
suspect = int((data["Tahmin"] != "BENIGN").sum())
a, b, c = st.columns(3)
a.metric("Toplam akış", len(data))
b.metric("Normal tahmini", normal)
c.metric("Saldırı tahmini", suspect)

st.subheader("Model tahminlerinin dağılımı")
st.bar_chart(data["Tahmin"].value_counts())
st.caption("Tahmin sayıları doğruluk oranı değildir.")

st.subheader("Kayıt özeti ve kural sonucu")
summary = selected.parent / "ozet.txt"
if summary.exists():
    st.text(summary.read_text(encoding="utf-8"))
else:
    st.info("Bu eski kayıtta özet dosyası yok; kural sonucu burada mevcut değil.")

st.subheader("Akış detayları")
only_suspect = st.checkbox("Yalnızca normal dışı model tahminlerini göster")
shown = data[data["Tahmin"] != "BENIGN"] if only_suspect else data

columns = [
    name for name in (
        "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "flow_duration", "Tahmin"
    ) if name in shown.columns
]
st.dataframe(shown[columns], hide_index=True)
st.caption("flow_duration saniye cinsindedir; model girişinde mikrosaniyeye çevrilir.")

st.download_button(
    "Sonuç CSV'sini indir",
    data=data.to_csv(index=False).encode("utf-8"),
    file_name=f"{selected.parent.name}_sonuclar.csv",
    mime="text/csv",
)

import argparse

import joblib
import pandas as pd

parser = argparse.ArgumentParser(description="CSV akışları için saldırı uyarıları")
parser.add_argument("csv", help="Kontrol edilecek CSV dosyası")
parser.add_argument("--model", default="models/uc_sinif_model.joblib")
args = parser.parse_args()

bundle = joblib.load(args.model)
data = pd.read_csv(args.csv, low_memory=False)
data.columns = data.columns.str.strip()

features = data.reindex(columns=bundle["columns"])
features = features.apply(pd.to_numeric, errors="coerce")
features = features.replace([float("inf"), float("-inf")], float("nan"))

predictions = bundle["pipeline"].predict(features)

for row_number, label in enumerate(predictions, start=1):
    if label != "BENIGN":
        print(f"UYARI | Satır {row_number} | {label}")

print(f"Kontrol edilen: {len(predictions)} | Uyarı: {sum(predictions != 'BENIGN')}")

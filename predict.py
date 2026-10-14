import argparse
import joblib
import pandas as pd

parser = argparse.ArgumentParser(description="Classify rows in a CSV using a trained model")
parser.add_argument("model")
parser.add_argument("csv")
args = parser.parse_args()
bundle = joblib.load(args.model)  # Only load model files you created or trust.
df = pd.read_csv(args.csv, low_memory=False)
df.columns = df.columns.str.strip()
X = df.reindex(columns=bundle["columns"])
X = X.apply(pd.to_numeric, errors="coerce").replace([float("inf"), float("-inf")], float("nan"))
for index, prediction in enumerate(bundle["pipeline"].predict(X)):
    print(f"row={index} prediction={prediction}")

import argparse
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline


def main():
    parser = argparse.ArgumentParser(description="Train a baseline network intrusion classifier")
    parser.add_argument("csv", type=Path)
    parser.add_argument("--label", default="Label", help="Name of target column")
    parser.add_argument("--model", type=Path, default=Path("model.joblib"))
    args = parser.parse_args()
    df = pd.read_csv(args.csv, low_memory=False)
    df.columns = df.columns.str.strip()
    label = args.label.strip()
    if label not in df:
        parser.error(f"Label column {label!r} missing. Columns: {list(df.columns)}")
    df = df.dropna(subset=[label])
    y = df[label].astype(str).str.strip()
    # Identifiers and timestamps can let a model memorize a capture instead of traffic behavior.
    excluded = {label.lower(), "flow id", "source ip", "destination ip", "src ip", "dst ip", "timestamp", "id"}
    candidates = df.drop(columns=[c for c in df if c.lower() in excluded])
    X = candidates.select_dtypes(include="number").replace([float("inf"), float("-inf")], float("nan"))
    X = X.dropna(axis=1, how="all")
    if len(X.columns) == 0 or y.nunique() < 2:
        parser.error("Need numeric feature columns and at least two labels")
    counts = y.value_counts()
    if len(df) < 20 or counts.min() < 2:
        parser.error("Need at least 20 rows and two rows per class for stratified evaluation")
    if (len(df) * 0.2) < y.nunique():
        parser.error("Need enough rows for each class in the test split")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    model = make_pipeline(SimpleImputer(strategy="median", add_indicator=True), RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1))
    model.fit(X_train, y_train)
    prediction = model.predict(X_test)
    print(classification_report(y_test, prediction, zero_division=0))
    print("Confusion matrix; label order:", list(model.classes_))
    print(confusion_matrix(y_test, prediction, labels=model.classes_))
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": model, "columns": list(X.columns)}, args.model)
    print("Saved:", args.model)


if __name__ == "__main__":
    main()

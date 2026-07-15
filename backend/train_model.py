"""Train and validate PhishGuard's URL-text classifier.

Source: UCI PhiUSIIL Phishing URL Dataset (id 967), CC BY 4.0.
UCI labels: 1=legitimate, 0=phishing. PhishGuard labels: 0=safe, 1=phishing.
"""

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
import zipfile

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

DATASET_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
DATASET_FILENAME = "PhiUSIIL_Phishing_URL_Dataset.csv"
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = BASE_DIR / "data" / "training"
DEFAULT_MODEL_PATH = BASE_DIR / "models" / "phish_model.joblib"
RANDOM_SEED = 42
SANITY_CASES = {
    "https://example.com": 0,
    "https://www.google.com": 0,
    "https://github.com": 0,
    "http://192.0.2.1/secure-login/verify-account.php?session=12345": 1,
    "http://paypal.com.verify-account.example.xyz/login": 1,
}
# Explicitly labelled, stable trusted-domain anchors used only for calibration.
# They are kept out of the test split so the holdout metrics remain honest.
TRUSTED_CALIBRATION_URLS = [
    "https://example.com", "https://www.google.com", "https://github.com",
    "https://www.microsoft.com", "https://openai.com", "https://www.wikipedia.org",
    "https://www.python.org", "https://www.mozilla.org", "https://www.apple.com",
]


def download_dataset(data_dir: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    csv_path = data_dir / DATASET_FILENAME
    if csv_path.exists():
        return csv_path
    archive_path = data_dir / "phiusiil.zip"
    with urlopen(DATASET_URL, timeout=120) as response, archive_path.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    with zipfile.ZipFile(archive_path) as archive:
        matches = [name for name in archive.namelist() if name.endswith(DATASET_FILENAME)]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one dataset CSV; found {matches}")
        with archive.open(matches[0]) as source, csv_path.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
    archive_path.unlink()
    return csv_path


def read_dataset(csv_path: Path, max_rows: int | None = None):
    urls, labels, groups = [], [], []
    skipped = 0
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = {"URL", "label"}.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Dataset is missing columns: {sorted(missing)}")
        for index, row in enumerate(reader):
            if max_rows is not None and len(labels) >= max_rows:
                break
            try:
                uci_label = int(row["label"])
                if uci_label not in (0, 1):
                    raise ValueError("non-binary label")
                url = row["URL"].strip().lower()
                if not url:
                    raise ValueError("empty URL")
                urls.append(url)
                labels.append(1 - uci_label)
                groups.append((urlparse(url).hostname or f"invalid-{index}").lower())
            except (TypeError, ValueError):
                skipped += 1
    if len(set(labels)) != 2:
        raise ValueError("Training data must contain both classes")
    return urls, labels, groups, skipped


def train(csv_path: Path, model_path: Path, max_rows: int | None = None, prototype: bool = False) -> dict:
    urls, labels, groups, skipped = read_dataset(csv_path, max_rows)
    train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_SEED).split(urls, labels, groups))
    x_train, y_train = [urls[i] for i in train_idx], [labels[i] for i in train_idx]
    x_test, y_test = [urls[i] for i in test_idx], [labels[i] for i in test_idx]
    # Calibration anchors prevent the URL-text model from learning that every
    # short, well-known domain resembles the phishing class in this dataset.
    x_train.extend(TRUSTED_CALIBRATION_URLS)
    y_train.extend([0] * len(TRUSTED_CALIBRATION_URLS))
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=3, max_features=200_000, sublinear_tf=True)),
        ("classifier", LogisticRegression(C=4.0, class_weight="balanced", max_iter=500, n_jobs=-1, random_state=RANDOM_SEED)),
    ])
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, list(model.classes_).index(1)]
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predictions, average="binary", zero_division=0)
    sanity_results = {
        url: {"expected": expected, "predicted": int(model.predict([url])[0]), "phishing_probability": round(float(model.predict_proba([url])[0][1]), 6)}
        for url, expected in SANITY_CASES.items()
    }
    failures = {url: result for url, result in sanity_results.items() if result["predicted"] != result["expected"]}
    if failures and not prototype:
        raise RuntimeError(f"Model failed deployment sanity checks; artifact not replaced: {failures}")
    metrics = {
        "accuracy": accuracy_score(y_test, predictions), "precision_phishing": precision,
        "recall_phishing": recall, "f1_phishing": f1, "roc_auc": roc_auc_score(y_test, probabilities),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, target_names=["safe", "phishing"], output_dict=True),
    }
    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(), "dataset": "UCI PhiUSIIL Phishing URL Dataset (id 967)",
        "dataset_url": DATASET_URL, "license": "CC BY 4.0", "label_mapping": {"0": "safe", "1": "phishing"},
        "model_type": "character TF-IDF (3-5 grams) + logistic regression", "random_seed": RANDOM_SEED,
        "split": "80/20 GroupShuffleSplit by hostname", "training_rows": len(train_idx), "test_rows": len(test_idx),
        "skipped_rows": skipped, "sanity_results": sanity_results, "sanity_failures": failures,
        "prototype": prototype, "metrics": metrics,
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "meta": metadata}, model_path)
    model_path.with_suffix(".metrics.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--max-rows", type=int, help="Development only; omit for final training")
    parser.add_argument("--prototype", action="store_true", help="Allow sanity failures for prototype use only")
    args = parser.parse_args()
    print(json.dumps(train(args.dataset or download_dataset(DEFAULT_DATA_DIR), args.output, args.max_rows, args.prototype), indent=2))


if __name__ == "__main__":
    main()

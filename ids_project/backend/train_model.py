#!/usr/bin/env python3
"""Train the ARP XGBoost model from verified ground-truth labels.

Usage:
  python train_model.py --dataset SDN-ARP-dataset.csv --output model.json

The dataset must contain either the deployed FEATURE_COLUMNS or raw ARP
columns that RawARPAdapter can derive. Labels must map to 0=benign and
1=attack and must contain both classes.
"""

import argparse
from pathlib import Path

import pandas as pd
import xgboost as xgb
from sklearn.metrics import precision_recall_curve, classification_report
from sklearn.model_selection import train_test_split

from adapters import RawARPAdapter
from features import FEATURE_COLUMNS


def optimal_threshold(model, features, labels, beta=2.0):
    probabilities = model.predict_proba(features)[:, 1]
    precision, recall, thresholds = precision_recall_curve(labels, probabilities)
    if len(thresholds) == 0:
        return 0.35
    beta_squared = beta ** 2
    scores = (1 + beta_squared) * precision[:-1] * recall[:-1]
    scores /= beta_squared * precision[:-1] + recall[:-1] + 1e-12
    index = scores.argmax()
    return float(max(0.05, min(0.95, thresholds[index])))


def train(dataset_path, output_path):
    frame = pd.read_json(dataset_path) if Path(dataset_path).suffix.lower() == ".json" else pd.read_csv(dataset_path)
    training = RawARPAdapter(frame).dataset()
    features = training[FEATURE_COLUMNS]
    labels = training["label"].astype(int)
    unique_labels = sorted(labels.unique().tolist())
    if unique_labels != [0, 1]:
        raise ValueError(
            "Training requires binary labels [0, 1], where 0=benign and 1=attack; "
            f"found {unique_labels}"
        )
    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )
    negative_count = int((y_train == 0).sum())
    positive_count = int((y_train == 1).sum())
    scale_pos_weight = negative_count / max(positive_count, 1)
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
    )
    model.fit(x_train, y_train)
    threshold = optimal_threshold(model, x_test, y_test)
    model.get_booster().set_attr(alert_threshold=str(threshold))
    model.save_model(output_path)
    predictions = (model.predict_proba(x_test)[:, 1] >= threshold).astype(int)
    print(f"saved_model={output_path}")
    print(f"samples={len(training)} benign={negative_count} attack={positive_count}")
    print(f"scale_pos_weight={scale_pos_weight:.6f} threshold={threshold:.6f}")
    print(classification_report(y_test, predictions, zero_division=0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", default=str(Path(__file__).with_name("model.json")))
    args = parser.parse_args()
    train(args.dataset, args.output)


if __name__ == "__main__":
    main()
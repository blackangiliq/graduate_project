"""OPTIONAL EXPERIMENT - fine-tune CodeBERT for function-level vulnerability detection.

Status: this script is NOT part of the tested application. It follows the standard
Hugging Face fine-tuning recipe but was not executed in the environment where the project
was built (it needs a GPU, a multi-GB download and a real dataset). Run it, check the
numbers yourself, and report what you measure.

Why it is here: the thesis title says "intelligent". The built-in classifier
(sca/ai/classifier.py) is a classical TF-IDF model; this script is the deep-learning
counterpart you can compare it with (same dataset, same split, compare F1).

Requirements (large):
    pip install torch transformers datasets scikit-learn

Dataset: a JSON Lines file with the fields func/target (PrimeVul, DiverseVul, Devign, BigVul)
or code/label. PrimeVul: https://github.com/DLVulDet/PrimeVul

Example (Google Colab with a T4 GPU is enough for a subset):
    python experiments/train_codebert.py --train primevul_train.jsonl \
        --valid primevul_valid.jsonl --epochs 3 --out codebert-vuln
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sca.ai.classifier import load_dataset  # noqa: E402  (same loader as the classical model)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--train", required=True)
    parser.add_argument("--valid", required=True)
    parser.add_argument("--model", default="microsoft/codebert-base")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--limit", type=int, default=0, help="use only the first N samples")
    parser.add_argument("--out", default="codebert-vuln")
    args = parser.parse_args()

    import numpy as np
    import torch
    from sklearn.metrics import f1_score, precision_score, recall_score
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, Trainer,
                              TrainingArguments)

    tokenizer = AutoTokenizer.from_pretrained(args.model)

    class CodeDataset(torch.utils.data.Dataset):
        def __init__(self, path: str) -> None:
            self.texts, self.labels = load_dataset(path, args.limit)

        def __len__(self) -> int:
            return len(self.texts)

        def __getitem__(self, index: int):
            item = tokenizer(self.texts[index], truncation=True, max_length=args.max_length,
                             padding="max_length", return_tensors="pt")
            item = {key: value.squeeze(0) for key, value in item.items()}
            item["labels"] = torch.tensor(self.labels[index])
            return item

    train_data, valid_data = CodeDataset(args.train), CodeDataset(args.valid)
    print("train: %d samples (%d vulnerable)   valid: %d samples (%d vulnerable)" % (
        len(train_data), sum(train_data.labels), len(valid_data), sum(valid_data.labels)))

    def metrics(prediction):
        predicted = np.argmax(prediction.predictions, axis=1)
        gold = prediction.label_ids
        return {"precision": precision_score(gold, predicted, zero_division=0),
                "recall": recall_score(gold, predicted, zero_division=0),
                "f1": f1_score(gold, predicted, zero_division=0)}

    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)
    trainer = Trainer(
        model=model,
        args=TrainingArguments(output_dir=args.out, num_train_epochs=args.epochs,
                               per_device_train_batch_size=args.batch_size,
                               per_device_eval_batch_size=args.batch_size * 2,
                               learning_rate=2e-5, weight_decay=0.01, logging_steps=50,
                               report_to=[]),
        train_dataset=train_data, eval_dataset=valid_data, compute_metrics=metrics)
    trainer.train()
    print(trainer.evaluate())
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    print("Saved to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

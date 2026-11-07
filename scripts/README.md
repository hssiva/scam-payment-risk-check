# scripts

Helper scripts (data generation, evaluation, audit verification). Local only, no network.

## generate_reference_data.py

Recreates the SYNTHETIC reference files in `sample-data/reference/` (`customers.json`,
`payees.json`, `mule_accounts.json`). The output is fully deterministic: it comes from tables in
the script and simple arithmetic, with no random numbers, so there is no seed and every run gives
identical files.

```
.venv/bin/python scripts/generate_reference_data.py                 # overwrite sample-data/reference/
.venv/bin/python scripts/generate_reference_data.py --out-dir DIR   # write somewhere else
```

`tests/test_generate_reference_data.py` fails if the script output ever differs from the
committed files. If you change the data, edit the script, rerun it, and commit both together.

## generate_training_data.py

Writes `sample-data/training/training_data.csv`: 5000 SYNTHETIC labelled payments, seed 42, from
documented scam and genuine patterns (assumptions are listed at the top of the script). It is
deterministic and kept separate from the evaluation scenarios.

```
.venv/bin/python scripts/generate_training_data.py [--out PATH] [--seed N] [--count N]
```

## train_model.py

Fits the logistic regression in plain Python (batch gradient descent, no new dependencies) on a
seeded 80/20 split and writes `models/risk_model_v1.json` and `models/risk_model_v1.sha256`,
then prints the coefficients and held-out metrics (about 20 seconds).

```
.venv/bin/python scripts/train_model.py [--data PATH] [--out-dir DIR] [--trained-at ISO_TIMESTAMP]
```

Training is deterministic: the same data gives the same coefficients; only `trained_at` (and so
the checksum) changes between runs unless `--trained-at` is fixed. Retrain whenever the feature
code in `scamcheck.model` or the training data changes, and commit the data and the model together.

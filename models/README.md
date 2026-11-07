# models

Model artifacts. JSON only (no pickle). Trained on SYNTHETIC data.

- `risk_model_v1.json`: logistic regression (features, coefficients, intercept, training data
  hash and held-out metrics), written by `scripts/train_model.py`.
- `risk_model_v1.sha256`: SHA-256 of the JSON file. The service checks it at load time; a
  mismatch, a missing file or a feature-list mismatch puts the service in `DEGRADED_RULES_ONLY`
  mode. Set `SCAMCHECK_MODEL_PATH` to load a different artifact (its `.sha256` sits beside it).

Treat this directory like code: whoever can rewrite both files can replace the model.

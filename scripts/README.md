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

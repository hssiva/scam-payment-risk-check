# Operations

## Configuration

## Logs

## Failure modes

### Reference data
- Files live in `sample-data/reference/` (SYNTHETIC). Set `SCAMCHECK_REFERENCE_DIR` to load them from another directory.
- A missing or malformed file raises `ReferenceDataError` at load time (callers must treat that as "cannot decide", i.e. HOLD).

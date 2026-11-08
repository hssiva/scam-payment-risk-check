Last login: Sat Nov  7 11:28:31 on ttys009

The default interactive shell is now zsh.
To update your account to use zsh, please run `chsh -s /bin/zsh`.
For more details, please visit https://support.apple.com/kb/HT208050.
host:~ user$ cd MyApps/scam-payment-risk-check/
host:scam-payment-risk-check user$ ls
CLAUDE.md		evidence		models			requirements-dev.txt	sample-data		src
config			Makefile		pyproject.toml		requirements.txt	scripts			tests
host:scam-payment-risk-check user$ less Makefile 
host:scam-payment-risk-check user$ grep -n "amount\|float\|Decimal" src/scamcheck/schemas.py
4:numbers, payee names and amounts cannot leak into responses or logs.
9:from decimal import Decimal
23:MAX_AMOUNT = Decimal("1000000")
48:    amount: Annotated[Decimal, Field(gt=0, le=MAX_AMOUNT, decimal_places=2)]
76:    risk_score: float | None
81:    latency_ms: float
146:    if field == "amount":
host:scam-payment-risk-check user$ grep -n "assert\|parametrize\|raises" tests/test_schemas.py
50:    assert isinstance(result, list)
56:    assert isinstance(result, PaymentRequest)
57:    assert result.amount == Decimal("250.50")
58:    assert result.timestamp.tzinfo is not None
59:    assert result.payee.bsb == "123456"
62:@pytest.mark.parametrize("amount", ["0.01", "1000000", 1000000, 12.5])
64:    assert isinstance(validate_request(mutated("amount", amount)), PaymentRequest)
67:@pytest.mark.parametrize(
104:    assert codes(validate_request(mutated(path, value))) == {expected}
109:    assert isinstance(result, list)
110:    assert result[0].field == "payee.bsb"
118:    assert codes(first) == {"AMOUNT_NOT_POSITIVE", "INVALID_BSB", "UNSUPPORTED_CURRENCY"}
119:    assert first == validate_request(raw)
122:@pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
123:def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
125:    assert isinstance(result, list)
126:    assert result
127:    assert all(isinstance(i, ValidationIssue) for i in result)
136:        assert secret not in dumped
157:    assert dumped["decision"] == "WARN"
158:    assert dumped["mode"] == "NORMAL"
163:    assert resp.request_id is None
164:    assert resp.risk_score is None
165:    assert resp.model_version is None
169:    with pytest.raises(ValidationError):
174:    with pytest.raises(ValidationError):
176:    with pytest.raises(ValidationError):
178:    with pytest.raises(ValidationError):
183:    assert {d.value for d in Decision} == {"ALLOW", "WARN", "HOLD", "REJECT"}
184:    assert {m.value for m in Mode} == {"NORMAL", "DEGRADED_RULES_ONLY"}
host:scam-payment-risk-check user$ .venv/bin/pytest -q
..................................................                                                                                                          [100%]
50 passed in 0.31s
host:scam-payment-risk-check user$ .venv/bin/python - <<'EOF'
> from scamcheck.schemas import validate_request
> 
> base = {
>     "request_id": "req-1", "timestamp": "2026-11-10T09:15:00+11:00",
>     "customer_id": "C1001", "amount": "100.10", "currency": "AUD",
>     "payee": {"name": "J Smith", "bsb": "000123", "account_number": "12345678"},
>     "channel": "mobile",
>     "session": {"on_active_call": False, "remote_access_detected": False, "new_device": False},
> }
> 
> def show(label, raw):
>     r = validate_request(raw)
>     if isinstance(r, list):
>         print(label, "-> REJECTED:", [getattr(i, "code", i) for i in r])
>     else:
>         print(label, "-> OK, amount =", repr(r.amount))
> 
> show("valid          ", base)
> show("no timezone    ", {**base, "timestamp": "2026-11-10T09:15:00"})
> show("3 decimals     ", {**base, "amount": "100.105"})
> EOF
valid           -> OK, amount = Decimal('100.10')
no timezone     -> REJECTED: ['NAIVE_TIMESTAMP']
3 decimals      -> REJECTED: ['AMOUNT_TOO_PRECISE']
host:scam-payment-risk-check user$ .venv/bin/python - <<'EOF'
> import json, re, pathlib
> ref = pathlib.Path("sample-data/reference")
> 
> def find(obj, key):
>     if isinstance(obj, dict):
>         if key in obj: yield obj
>         for v in obj.values(): yield from find(v, key)
>     elif isinstance(obj, list):
>         for v in obj: yield from find(v, key)
> 
> cust = json.loads((ref / "customers.json").read_text())
> print("CUSTOMERS")
> print("id        tenure_days  typical_amount  known_payees")
> for c in find(cust, "customer_id"):
>     print(f"{c['customer_id']:<9} {c.get('tenure_days', '?'):>11}  {c.get('typical_payment_amount', '?'):>14}  {len(c.get('known_payees', [])):>12}")
> 
> print("\nBSBs AND SYNTHETIC LABELS")
> for name in ("customers.json", "payees.json", "mule_accounts.json"):
>     text = (ref / name).read_text()
>     bsbs = set(re.findall(r'"bsb"\s*:\s*"(\d+)"', text)) | set(re.findall(r'"(\d{6})-\d{6,9}"', text))
>     bad = sorted(b for b in bsbs if not b.startswith("000"))
>     print(f"{name:<20} BSBs found: {len(bsbs):>3}   not 000xxx: {bad or 'none'}   SYNTHETIC label: {'SYNTHETIC' in text}")
> EOF
CUSTOMERS
id        tenure_days  typical_amount  known_payees
cust-001         1800           150.0             4
cust-002         3200           420.0             5
cust-003           20            60.0             0
cust-004          900            85.5             2
cust-005         2600          1200.0             4
cust-006          400           250.0             2
cust-007         5100            95.0             3
cust-008          150           500.0             1
cust-009         1200          2000.0             3
cust-010          700           300.0             4

BSBs AND SYNTHETIC LABELS
customers.json       BSBs found:   3   not 000xxx: none   SYNTHETIC label: True
payees.json          BSBs found:   4   not 000xxx: none   SYNTHETIC label: True
mule_accounts.json   BSBs found:   2   not 000xxx: none   SYNTHETIC label: True
host:scam-payment-risk-check user$ grep -n "def " src/scamcheck/signals.py
38:def normalise_name(name: str) -> list[str]:
46:def _tokens_match(a: str, b: str) -> bool:
50:def name_match(
63:def build_signals(
host:scam-payment-risk-check user$ .venv/bin/python - <<'EOF'
> from scamcheck import signals
> fn = signals.match_payee_name   # <- change if the function has a different name
> cases = [
>     ("John Smith",     "John Smith",       "MATCH"),
>     ("john  smith.",   "JOHN SMITH",       "MATCH"),
>     ("J Smith",        "John Smith",       "CLOSE"),
>     ("Smith, John",    "John Smith",       "CLOSE"),
>     ("Jon Smith",      "John Smith",       "CLOSE"),
>     ("ACME Pty Ltd",   "Acme Pty. Ltd.",   "MATCH"),
>     ("Jane Doe",       "John Smith",       "MISMATCH"),
>     ("John Smith",     "Smith Holdings",   "MISMATCH"),
> ]
> for entered, actual, expected in cases:
>     got = fn(entered, actual)
>     got = getattr(got, "value", got)
>     flag = "ok " if str(got) == expected else "<<<"
>     print(f"{flag} {entered!r:18} vs {actual!r:18} -> {got}   (expected {expected})")
> EOF
Traceback (most recent call last):
  File "<stdin>", line 2, in <module>
AttributeError: module 'scamcheck.signals' has no attribute 'match_payee_name'
host:scam-payment-risk-check user$ .venv/bin/python - <<'EOF'
> from scamcheck import signals
> fn = signals.name_match   # <- change if the function has a different name
> cases = [
>     ("John Smith",     "John Smith",       "MATCH"),
>     ("john  smith.",   "JOHN SMITH",       "MATCH"),
>     ("J Smith",        "John Smith",       "CLOSE"),
>     ("Smith, John",    "John Smith",       "CLOSE"),
>     ("Jon Smith",      "John Smith",       "CLOSE"),
>     ("ACME Pty Ltd",   "Acme Pty. Ltd.",   "MATCH"),
>     ("Jane Doe",       "John Smith",       "MISMATCH"),
>     ("John Smith",     "Smith Holdings",   "MISMATCH"),
> ]
> for entered, actual, expected in cases:
>     got = fn(entered, actual)
>     got = getattr(got, "value", got)
>     flag = "ok " if str(got) == expected else "<<<"
>     print(f"{flag} {entered!r:18} vs {actual!r:18} -> {got}   (expected {expected})")
> EOF
ok  'John Smith'       vs 'John Smith'       -> MATCH   (expected MATCH)
ok  'john  smith.'     vs 'JOHN SMITH'       -> MATCH   (expected MATCH)
<<< 'J Smith'          vs 'John Smith'       -> MATCH   (expected CLOSE)
<<< 'Smith, John'      vs 'John Smith'       -> MISMATCH   (expected CLOSE)
ok  'Jon Smith'        vs 'John Smith'       -> CLOSE   (expected CLOSE)
ok  'ACME Pty Ltd'     vs 'Acme Pty. Ltd.'   -> MATCH   (expected MATCH)
ok  'Jane Doe'         vs 'John Smith'       -> MISMATCH   (expected MISMATCH)
ok  'John Smith'       vs 'Smith Holdings'   -> MISMATCH   (expected MISMATCH)
host:scam-payment-risk-check user$ grep -n "amount_ratio\|typical" src/scamcheck/signals.py
28:    amount_ratio: Decimal | None
73:    amount_ratio = (
74:        (request.amount / customer.typical_payment_amount).quantize(_RATIO_PLACES)
85:        amount_ratio=amount_ratio,
host:scam-payment-risk-check user$ grep -n "unknown\|data_complete\|amount_ratio" tests/*.py
tests/test_schemas.py:173:def test_decision_response_rejects_unknown_field_and_bad_enum() -> None:
tests/test_signals.py:66:def test_amount_ratio_is_decimal_and_quantised() -> None:
tests/test_signals.py:68:    assert signals.amount_ratio == Decimal("3.0000")
tests/test_signals.py:69:    assert isinstance(signals.amount_ratio, Decimal)
tests/test_signals.py:70:    third = build_signals(request(amount="100.00"), reference()).amount_ratio
tests/test_signals.py:110:    assert build_signals(request(), reference()).data_complete is True
tests/test_signals.py:113:def test_unknown_customer_is_incomplete_and_treated_as_new_payee() -> None:
tests/test_signals.py:115:    assert signals.data_complete is False
tests/test_signals.py:116:    assert signals.amount_ratio is None
tests/test_signals.py:121:def test_unknown_payee_is_incomplete_and_name_unavailable() -> None:
tests/test_signals.py:123:    assert signals.data_complete is False
tests/test_signals.py:127:    assert signals.amount_ratio == Decimal("1.0000")
tests/test_signals.py:133:    assert signals.data_complete is False
tests/test_signals.py:136:def test_unknown_customer_and_payee() -> None:
tests/test_signals.py:138:    assert signals.data_complete is False
tests/test_signals.py:140:    assert signals.amount_ratio is None
host:scam-payment-risk-check user$ grep -n "typical" src/scamcheck/signals.py
74:        (request.amount / customer.typical_payment_amount).quantize(_RATIO_PLACES)
host:scam-payment-risk-check user$ grep -n "def " src/scamcheck/signals.py
38:def normalise_name(name: str) -> list[str]:
46:def _tokens_match(a: str, b: str) -> bool:
50:def name_match(
63:def build_signals(
host:scam-payment-risk-check user$ grep -rn "TODO\|0\.8\|MAX_AMOUNT" src/
src/scamcheck/signals.py:13:# TODO: move to config/policy.toml once the policy loader exists.
src/scamcheck/signals.py:14:DEFAULT_CLOSE_THRESHOLD = 0.80
Binary file src/scamcheck/__pycache__/schemas.cpython-312.pyc matches
src/scamcheck/schemas.py:22:# TODO: move to config/policy.toml once the policy loader exists.
src/scamcheck/schemas.py:23:MAX_AMOUNT = Decimal("1000000")
src/scamcheck/schemas.py:48:    amount: Annotated[Decimal, Field(gt=0, le=MAX_AMOUNT, decimal_places=2)]
host:scam-payment-risk-check user$ ls scripts/
README.md
host:scam-payment-risk-check user$ The data generator isn't in the repo: scripts/ only has README.md. Add it as
> scripts/generate_reference_data.py, with a fixed seed, so it recreates exactly the current
> files in sample-data/reference/. Update scripts/README.md with how to run it. Run make verify.
> 
host:scam-payment-risk-check user$ .venv/bin/python scripts/generate_reference_data.py
wrote /Users/user/MyApps/scam-payment-risk-check/sample-data/reference/customers.json
wrote /Users/user/MyApps/scam-payment-risk-check/sample-data/reference/payees.json
wrote /Users/user/MyApps/scam-payment-risk-check/sample-data/reference/mule_accounts.json
host:scam-payment-risk-check user$ git diff --stat sample-data/
host:scam-payment-risk-check user$ less config/policy.toml
host:scam-payment-risk-check user$ vi config/policy.toml
host:scam-payment-risk-check user$ grep -nE "[^a-zA-Z_][0-9]{2,}" src/scamcheck/rules.py src/scamcheck/engine.py
src/scamcheck/engine.py:29:_MAX_ID_LENGTH = 64
src/scamcheck/engine.py:68:        latency_ms=round((time.perf_counter() - meta.started) * 1000, 3),
host:scam-payment-risk-check user$ grep -rn "TODO" src/
src/scamcheck/signals.py:13:# TODO: move to config/policy.toml once the policy loader exists.
host:scam-payment-risk-check user$ grep -nE ">=|<=| > | < " src/scamcheck/rules.py
32:    """The most severe decision (ALLOW < WARN < HOLD); ALLOW if the list is empty."""
62:    if signals.on_active_call and signals.new_payee and amount >= policy.high_value_amount:
79:    high_value = amount >= policy.high_value_amount
93:    if signals.amount_ratio is not None and signals.amount_ratio >= policy.unusual_ratio:
109:    if signals.new_payee and age is not None and age < policy.young_account_days:
host:scam-payment-risk-check user$ grep -nE "4999|5000|5001|999|1000|29|30|31" tests/test_rules.py tests/test_engine.py
tests/test_rules.py:23:    high_value_amount=Decimal("5000"),
tests/test_rules.py:24:    abstain_amount=Decimal("1000"),
tests/test_rules.py:26:    young_account_days=30,
tests/test_rules.py:29:    max_amount=Decimal("1000000"),
tests/test_rules.py:32:HIGH = Decimal("5000")
tests/test_rules.py:39:        "payee_account_age_days": 1000,
tests/test_rules.py:86:    assert r03_on_call_new_payee_high_value(sig, Decimal("4999.99"), POLICY) is None
tests/test_rules.py:99:    hit = r04_payee_name_mismatch(sig, Decimal("4999.99"), POLICY)
tests/test_rules.py:121:    assert r05_unusual_amount(signals(amount_ratio=Decimal("4.9999")), SMALL, POLICY) is None
tests/test_rules.py:129:    hit = r06_young_payee_account(signals(new_payee=True, payee_account_age_days=29), SMALL, POLICY)
tests/test_rules.py:138:        {"new_payee": True, "payee_account_age_days": 30},  # exactly at threshold
tests/test_engine.py:89:    response = assess(raw_request("cust-009", NEW_OLD, "5000.00", on_active_call=True))
tests/test_engine.py:95:    response = assess(raw_request("cust-009", NEW_OLD, "4999.99", on_active_call=True))
tests/test_engine.py:109:    response = assess(raw_request("cust-009", payee, "5000.00"))
tests/test_engine.py:148:    response = assess(raw_request("ghost", KNOWN_001, "1000.00"))
tests/test_engine.py:155:    response = assess(raw_request("cust-001", unknown, "1000.00"))
tests/test_engine.py:161:    response = assess(raw_request("ghost", KNOWN_001, "999.99"))
tests/test_engine.py:191:    response = assess(raw_request("cust-001", KNOWN_001, "1000000.01"))
tests/test_engine.py:217:        raw_request("ghost", KNOWN_001, "5000.00"),
host:scam-payment-risk-check user$ ls tests
__pycache__			test_generate_reference_data.py	test_reference.py		test_schemas.py			test_version.py
test_engine.py			test_policy.py			test_rules.py			test_signals.py
host:scam-payment-risk-check user$ .venv/bin/pytest -q
.....F...............................F.......................................................FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF......FFFFFFFFFFFF [ 89%]
...................                                                                                                                                         [100%]
============================================================================ FAILURES =============================================================================
__________________________________________________________ test_r03_just_below_high_value_does_not_fire ___________________________________________________________

    def test_r03_just_below_high_value_does_not_fire() -> None:
        response = assess(raw_request("cust-009", NEW_OLD, "4999.99", on_active_call=True))
>       assert "R03_ON_CALL_NEW_PAYEE_HIGH_VALUE" not in codes(response)
E       AssertionError: assert 'R03_ON_CALL_NEW_PAYEE_HIGH_VALUE' not in ['R03_ON_CALL_NEW_PAYEE_HIGH_VALUE']
E        +  where ['R03_ON_CALL_NEW_PAYEE_HIGH_VALUE'] = codes(DecisionResponse(decision_id='22c344ed-df8e-4553-99be-3ce4b5b05d79', request_id='req-1', decision=<Decision.HOLD: 'HOL...s 3000 AUD or more).')], mode=<Mode.NORMAL: 'NORMAL'>, model_version=None, policy_version='2026.11.1', latency_ms=1.33))

tests/test_engine.py:96: AssertionError
_____________________________________________________________________ test_real_policy_values _____________________________________________________________________

    def test_real_policy_values() -> None:
        policy = load_policy()
        assert policy.policy_version == "2026.11.1"
>       assert policy.high_value_amount == Decimal("5000")
E       AssertionError: assert Decimal('3000') == Decimal('5000')
E        +  where Decimal('3000') = Policy(policy_version='2026.11.1', high_value_amount=Decimal('3000'), abstain_amount=Decimal('1000'), unusual_ratio=Decimal('5'), young_account_days=30, score_warn=0.35, score_hold=0.7, max_amount=Decimal('1000000')).high_value_amount
E        +  and   Decimal('5000') = Decimal('5000')

tests/test_policy.py:29: AssertionError
____________________________________________________________________ test_valid_request_parses ____________________________________________________________________

    def test_valid_request_parses() -> None:
>       result = validate_request(valid_raw())
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:55: TypeError
_______________________________________________________________ test_valid_amount_boundaries[0.01] ________________________________________________________________

amount = '0.01'

    @pytest.mark.parametrize("amount", ["0.01", "1000000", 1000000, 12.5])
    def test_valid_amount_boundaries(amount: Any) -> None:
>       assert isinstance(validate_request(mutated("amount", amount)), PaymentRequest)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:64: TypeError
_____________________________________________________________ test_valid_amount_boundaries[1000000_0] _____________________________________________________________

amount = '1000000'

    @pytest.mark.parametrize("amount", ["0.01", "1000000", 1000000, 12.5])
    def test_valid_amount_boundaries(amount: Any) -> None:
>       assert isinstance(validate_request(mutated("amount", amount)), PaymentRequest)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:64: TypeError
_____________________________________________________________ test_valid_amount_boundaries[1000000_1] _____________________________________________________________

amount = 1000000

    @pytest.mark.parametrize("amount", ["0.01", "1000000", 1000000, 12.5])
    def test_valid_amount_boundaries(amount: Any) -> None:
>       assert isinstance(validate_request(mutated("amount", amount)), PaymentRequest)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:64: TypeError
_______________________________________________________________ test_valid_amount_boundaries[12.5] ________________________________________________________________

amount = 12.5

    @pytest.mark.parametrize("amount", ["0.01", "1000000", 1000000, 12.5])
    def test_valid_amount_boundaries(amount: Any) -> None:
>       assert isinstance(validate_request(mutated("amount", amount)), PaymentRequest)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:64: TypeError
__________________________________________________ test_invalid_input_maps_to_code[payee.bsb-12345-INVALID_BSB] ___________________________________________________

path = 'payee.bsb', value = '12345', expected = 'INVALID_BSB'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________________ test_invalid_input_maps_to_code[payee.bsb-12345a-INVALID_BSB] __________________________________________________

path = 'payee.bsb', value = '12345a', expected = 'INVALID_BSB'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
___________________________________ test_invalid_input_maps_to_code[payee.bsb-\u0661\u0662\u0663\u0664\u0665\u0666-INVALID_BSB] ___________________________________

path = 'payee.bsb', value = '١٢٣٤٥٦', expected = 'INVALID_BSB'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_______________________________________ test_invalid_input_maps_to_code[payee.account_number-12345-INVALID_ACCOUNT_NUMBER] ________________________________________

path = 'payee.account_number', value = '12345', expected = 'INVALID_ACCOUNT_NUMBER'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_____________________________________ test_invalid_input_maps_to_code[payee.account_number-1234567890-INVALID_ACCOUNT_NUMBER] _____________________________________

path = 'payee.account_number', value = '1234567890', expected = 'INVALID_ACCOUNT_NUMBER'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_________________________________________________ test_invalid_input_maps_to_code[payee.name--INVALID_PAYEE_NAME] _________________________________________________

path = 'payee.name', value = '', expected = 'INVALID_PAYEE_NAME'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
______________________________________________ test_invalid_input_maps_to_code[payee.name-value6-INVALID_PAYEE_NAME] ______________________________________________

path = 'payee.name'
value = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
expected = 'INVALID_PAYEE_NAME'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________________ test_invalid_input_maps_to_code[amount-0-AMOUNT_NOT_POSITIVE] __________________________________________________

path = 'amount', value = 0, expected = 'AMOUNT_NOT_POSITIVE'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
________________________________________________ test_invalid_input_maps_to_code[amount--5.00-AMOUNT_NOT_POSITIVE] ________________________________________________

path = 'amount', value = '-5.00', expected = 'AMOUNT_NOT_POSITIVE'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_______________________________________________ test_invalid_input_maps_to_code[amount-1000000.01-AMOUNT_TOO_LARGE] _______________________________________________

path = 'amount', value = '1000000.01', expected = 'AMOUNT_TOO_LARGE'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
________________________________________________ test_invalid_input_maps_to_code[amount-10.001-AMOUNT_TOO_PRECISE] ________________________________________________

path = 'amount', value = '10.001', expected = 'AMOUNT_TOO_PRECISE'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
___________________________________________________ test_invalid_input_maps_to_code[amount-abc-AMOUNT_INVALID] ____________________________________________________

path = 'amount', value = 'abc', expected = 'AMOUNT_INVALID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
___________________________________________________ test_invalid_input_maps_to_code[amount-NaN-AMOUNT_INVALID] ____________________________________________________

path = 'amount', value = 'NaN', expected = 'AMOUNT_INVALID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_________________________________________________ test_invalid_input_maps_to_code[amount-Infinity-AMOUNT_INVALID] _________________________________________________

path = 'amount', value = 'Infinity', expected = 'AMOUNT_INVALID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_________________________________________ test_invalid_input_maps_to_code[timestamp-2026-03-01T10:15:00-NAIVE_TIMESTAMP] __________________________________________

path = 'timestamp', value = '2026-03-01T10:15:00', expected = 'NAIVE_TIMESTAMP'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_____________________________________________ test_invalid_input_maps_to_code[timestamp-not-a-date-INVALID_TIMESTAMP] _____________________________________________

path = 'timestamp', value = 'not-a-date', expected = 'INVALID_TIMESTAMP'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_______________________________________________ test_invalid_input_maps_to_code[currency-USD-UNSUPPORTED_CURRENCY] ________________________________________________

path = 'currency', value = 'USD', expected = 'UNSUPPORTED_CURRENCY'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________________ test_invalid_input_maps_to_code[channel-atm-INVALID_CHANNEL] ___________________________________________________

path = 'channel', value = 'atm', expected = 'INVALID_CHANNEL'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_________________________________________________ test_invalid_input_maps_to_code[request_id--INVALID_REQUEST_ID] _________________________________________________

path = 'request_id', value = '', expected = 'INVALID_REQUEST_ID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
________________ test_invalid_input_maps_to_code[request_id-rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr-INVALID_REQUEST_ID] _________________

path = 'request_id', value = 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr', expected = 'INVALID_REQUEST_ID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_______________________________________________ test_invalid_input_maps_to_code[request_id-123-INVALID_REQUEST_ID] ________________________________________________

path = 'request_id', value = 123, expected = 'INVALID_REQUEST_ID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
________________________________________________ test_invalid_input_maps_to_code[customer_id--INVALID_CUSTOMER_ID] ________________________________________________

path = 'customer_id', value = '', expected = 'INVALID_CUSTOMER_ID'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________ test_invalid_input_maps_to_code[session.new_device-yes-INVALID_SESSION_FLAG] ___________________________________________

path = 'session.new_device', value = 'yes', expected = 'INVALID_SESSION_FLAG'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_________________________________________ test_invalid_input_maps_to_code[session.on_active_call-1-INVALID_SESSION_FLAG] __________________________________________

path = 'session.on_active_call', value = 1, expected = 'INVALID_SESSION_FLAG'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________________ test_invalid_input_maps_to_code[payee-someone-INVALID_PAYEE] ___________________________________________________

path = 'payee', value = 'someone', expected = 'INVALID_PAYEE'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________________ test_invalid_input_maps_to_code[session-None-INVALID_SESSION] __________________________________________________

path = 'session', value = None, expected = 'INVALID_SESSION'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
____________________________________________________ test_invalid_input_maps_to_code[surprise-x-UNKNOWN_FIELD] ____________________________________________________

path = 'surprise', value = 'x', expected = 'UNKNOWN_FIELD'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_________________________________________________ test_invalid_input_maps_to_code[payee.nickname-x-UNKNOWN_FIELD] _________________________________________________

path = 'payee.nickname', value = 'x', expected = 'UNKNOWN_FIELD'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_____________________________________________ test_invalid_input_maps_to_code[session.extra_flag-True-UNKNOWN_FIELD] ______________________________________________

path = 'session.extra_flag', value = True, expected = 'UNKNOWN_FIELD'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
__________________________________________________ test_invalid_input_maps_to_code[amount-value29-MISSING_FIELD] __________________________________________________

path = 'amount', value = <object object at 0x102b91e10>, expected = 'MISSING_FIELD'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
________________________________________________ test_invalid_input_maps_to_code[payee.bsb-value30-MISSING_FIELD] _________________________________________________

path = 'payee.bsb', value = <object object at 0x102b91e10>, expected = 'MISSING_FIELD'

    @pytest.mark.parametrize(
        ("path", "value", "expected"),
        [
            ("payee.bsb", "12345", "INVALID_BSB"),
            ("payee.bsb", "12345a", "INVALID_BSB"),
            ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
            ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
            ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
            ("payee.name", "", "INVALID_PAYEE_NAME"),
            ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
            ("amount", 0, "AMOUNT_NOT_POSITIVE"),
            ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
            ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
            ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
            ("amount", "abc", "AMOUNT_INVALID"),
            ("amount", "NaN", "AMOUNT_INVALID"),
            ("amount", "Infinity", "AMOUNT_INVALID"),
            ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
            ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
            ("currency", "USD", "UNSUPPORTED_CURRENCY"),
            ("channel", "atm", "INVALID_CHANNEL"),
            ("request_id", "", "INVALID_REQUEST_ID"),
            ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
            ("request_id", 123, "INVALID_REQUEST_ID"),
            ("customer_id", "", "INVALID_CUSTOMER_ID"),
            ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
            ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
            ("payee", "someone", "INVALID_PAYEE"),
            ("session", None, "INVALID_SESSION"),
            ("surprise", "x", "UNKNOWN_FIELD"),
            ("payee.nickname", "x", "UNKNOWN_FIELD"),
            ("session.extra_flag", True, "UNKNOWN_FIELD"),
            ("amount", _DELETE, "MISSING_FIELD"),
            ("payee.bsb", _DELETE, "MISSING_FIELD"),
        ],
    )
    def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
>       assert codes(validate_request(mutated(path, value))) == {expected}
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:104: TypeError
_______________________________________________________________ test_issue_field_paths_are_reported _______________________________________________________________

    def test_issue_field_paths_are_reported() -> None:
>       result = validate_request(mutated("payee.bsb", "1"))
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:108: TypeError
_______________________________________________________ test_multiple_issues_all_reported_and_deterministic _______________________________________________________

    def test_multiple_issues_all_reported_and_deterministic() -> None:
        raw = mutated("amount", "-1")
        raw["payee"]["bsb"] = "1"
        raw["currency"] = "USD"
>       first = validate_request(raw)
                ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:117: TypeError
________________________________________________________ test_non_object_or_empty_input_never_raises[None] ________________________________________________________

raw = None

    @pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
    def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:124: TypeError
________________________________________________________ test_non_object_or_empty_input_never_raises[raw1] ________________________________________________________

raw = []

    @pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
    def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:124: TypeError
________________________________________________________ test_non_object_or_empty_input_never_raises[text] ________________________________________________________

raw = 'text'

    @pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
    def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:124: TypeError
_________________________________________________________ test_non_object_or_empty_input_never_raises[42] _________________________________________________________

raw = 42

    @pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
    def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:124: TypeError
________________________________________________________ test_non_object_or_empty_input_never_raises[raw4] ________________________________________________________

raw = {}

    @pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
    def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:124: TypeError
______________________________________________________________ test_issues_do_not_leak_input_values _______________________________________________________________

    def test_issues_do_not_leak_input_values() -> None:
        raw = mutated("payee.account_number", "99999")
        raw["amount"] = "7777.123"
        raw["payee"]["name"] = ""
>       dumped = " ".join(i.model_dump_json() for i in validate_request(raw))  # type: ignore[union-attr]
                                                       ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_schemas.py:134: TypeError
___________________________________________________________________ test_known_payee_is_not_new ___________________________________________________________________

    def test_known_payee_is_not_new() -> None:
>       assert build_signals(request(), reference()).new_payee is False
                             ^^^^^^^^^

tests/test_signals.py:59: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
____________________________________________________________________ test_unseen_payee_is_new _____________________________________________________________________

    def test_unseen_payee_is_new() -> None:
>       assert build_signals(request(payee=OTHER, name="x"), reference()).new_payee is True
                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

tests/test_signals.py:63: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-22222222', amount = '150.00', name = 'x', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
___________________________________________________________ test_amount_ratio_is_decimal_and_quantised ____________________________________________________________

    def test_amount_ratio_is_decimal_and_quantised() -> None:
>       signals = build_signals(request(amount="450.00"), reference())
                                ^^^^^^^^^^^^^^^^^^^^^^^^

tests/test_signals.py:67: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '450.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
____________________________________________________________ test_payee_account_age_is_passed_through _____________________________________________________________

    def test_payee_account_age_is_passed_through() -> None:
>       assert build_signals(request(), reference()).payee_account_age_days == 1000
                             ^^^^^^^^^

tests/test_signals.py:75: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
________________________________________________________________ test_name_match_uses_account_name ________________________________________________________________

    def test_name_match_uses_account_name() -> None:
>       assert build_signals(request(), reference()).payee_name_match is NameMatch.MATCH
                             ^^^^^^^^^

tests/test_signals.py:80: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
_________________________________________________________________________ test_mule_flag __________________________________________________________________________

    def test_mule_flag() -> None:
>       assert build_signals(request(), reference()).payee_on_mule_list is False
                             ^^^^^^^^^

tests/test_signals.py:88: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
__________________________________________________________________ test_session_flags_are_copied __________________________________________________________________

    def test_session_flags_are_copied() -> None:
        signals = build_signals(
>           request(on_active_call=True, remote_access_detected=True, new_device=True), reference()
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        )

tests/test_signals.py:94: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '150.00', name = 'John Smith'
session = {'on_active_call': True, 'remote_access_detected': True, 'new_device': True}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
_______________________________________________________________________ test_complete_data ________________________________________________________________________

    def test_complete_data() -> None:
>       assert build_signals(request(), reference()).data_complete is True
                             ^^^^^^^^^

tests/test_signals.py:110: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-11111111', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
__________________________________________________ test_unknown_customer_is_incomplete_and_treated_as_new_payee ___________________________________________________

    def test_unknown_customer_is_incomplete_and_treated_as_new_payee() -> None:
>       signals = build_signals(request(customer_id="ghost"), reference())
                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

tests/test_signals.py:114: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'ghost', payee = '000111-11111111', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
______________________________________________________ test_unknown_payee_is_incomplete_and_name_unavailable ______________________________________________________

    def test_unknown_payee_is_incomplete_and_name_unavailable() -> None:
>       signals = build_signals(request(payee="000111-33333333"), reference())
                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

tests/test_signals.py:122: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000111-33333333', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
____________________________________________________ test_mule_list_applies_even_if_payee_is_not_in_reference _____________________________________________________

    def test_mule_list_applies_even_if_payee_is_not_in_reference() -> None:
>       signals = build_signals(request(payee=MULE_ONLY), reference())
                                ^^^^^^^^^^^^^^^^^^^^^^^^

tests/test_signals.py:131: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'c1', payee = '000199-99999999', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
_________________________________________________________________ test_unknown_customer_and_payee _________________________________________________________________

    def test_unknown_customer_and_payee() -> None:
>       signals = build_signals(request(customer_id="ghost", payee="000111-33333333"), reference())
                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

tests/test_signals.py:137: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

customer_id = 'ghost', payee = '000111-33333333', amount = '150.00', name = 'John Smith', session = {}

    def request(
        *,
        customer_id: str = "c1",
        payee: str = KNOWN,
        amount: str = "150.00",
        name: str = "John Smith",
        **session: bool,
    ) -> PaymentRequest:
        bsb, account = payee.split("-")
        raw: dict[str, Any] = {
            "request_id": "r1",
            "timestamp": "2026-03-01T10:00:00+11:00",
            "customer_id": customer_id,
            "amount": amount,
            "currency": "AUD",
            "payee": {"name": name, "bsb": bsb, "account_number": account},
            "channel": "web",
            "session": {
                "on_active_call": False,
                "remote_access_detected": False,
                "new_device": False,
            }
            | session,
        }
>       result = validate_request(raw)
                 ^^^^^^^^^^^^^^^^^^^^^
E       TypeError: validate_request() missing 1 required positional argument: 'max_amount'

tests/test_signals.py:53: TypeError
===================================================================== short test summary info =====================================================================
FAILED tests/test_engine.py::test_r03_just_below_high_value_does_not_fire - AssertionError: assert 'R03_ON_CALL_NEW_PAYEE_HIGH_VALUE' not in ['R03_ON_CALL_NEW_PAYEE_HIGH_VALUE']
FAILED tests/test_policy.py::test_real_policy_values - AssertionError: assert Decimal('3000') == Decimal('5000')
FAILED tests/test_schemas.py::test_valid_request_parses - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_valid_amount_boundaries[0.01] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_valid_amount_boundaries[1000000_0] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_valid_amount_boundaries[1000000_1] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_valid_amount_boundaries[12.5] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.bsb-12345-INVALID_BSB] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.bsb-12345a-INVALID_BSB] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.bsb-\u0661\u0662\u0663\u0664\u0665\u0666-INVALID_BSB] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.account_number-12345-INVALID_ACCOUNT_NUMBER] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.account_number-1234567890-INVALID_ACCOUNT_NUMBER] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.name--INVALID_PAYEE_NAME] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.name-value6-INVALID_PAYEE_NAME] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-0-AMOUNT_NOT_POSITIVE] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount--5.00-AMOUNT_NOT_POSITIVE] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-1000000.01-AMOUNT_TOO_LARGE] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-10.001-AMOUNT_TOO_PRECISE] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-abc-AMOUNT_INVALID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-NaN-AMOUNT_INVALID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-Infinity-AMOUNT_INVALID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[timestamp-2026-03-01T10:15:00-NAIVE_TIMESTAMP] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[timestamp-not-a-date-INVALID_TIMESTAMP] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[currency-USD-UNSUPPORTED_CURRENCY] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[channel-atm-INVALID_CHANNEL] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[request_id--INVALID_REQUEST_ID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[request_id-rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr-INVALID_REQUEST_ID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[request_id-123-INVALID_REQUEST_ID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[customer_id--INVALID_CUSTOMER_ID] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[session.new_device-yes-INVALID_SESSION_FLAG] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[session.on_active_call-1-INVALID_SESSION_FLAG] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee-someone-INVALID_PAYEE] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[session-None-INVALID_SESSION] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[surprise-x-UNKNOWN_FIELD] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.nickname-x-UNKNOWN_FIELD] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[session.extra_flag-True-UNKNOWN_FIELD] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[amount-value29-MISSING_FIELD] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_invalid_input_maps_to_code[payee.bsb-value30-MISSING_FIELD] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_issue_field_paths_are_reported - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_multiple_issues_all_reported_and_deterministic - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_non_object_or_empty_input_never_raises[None] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_non_object_or_empty_input_never_raises[raw1] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_non_object_or_empty_input_never_raises[text] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_non_object_or_empty_input_never_raises[42] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_non_object_or_empty_input_never_raises[raw4] - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_schemas.py::test_issues_do_not_leak_input_values - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_known_payee_is_not_new - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_unseen_payee_is_new - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_amount_ratio_is_decimal_and_quantised - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_payee_account_age_is_passed_through - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_name_match_uses_account_name - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_mule_flag - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_session_flags_are_copied - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_complete_data - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_unknown_customer_is_incomplete_and_treated_as_new_payee - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_unknown_payee_is_incomplete_and_name_unavailable - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_mule_list_applies_even_if_payee_is_not_in_reference - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
FAILED tests/test_signals.py::test_unknown_customer_and_payee - TypeError: validate_request() missing 1 required positional argument: 'max_amount'
58 failed, 116 passed in 1.44s
host:scam-payment-risk-check user$ .venv/bin/pytest -q
........................................................................................................................................................... [ 86%]
........................                                                                                                                                    [100%]
179 passed in 0.84s
host:scam-payment-risk-check user$ git diff src/
diff --git a/src/scamcheck/reference.py b/src/scamcheck/reference.py
index 8bfa46f..2b8465b 100644
--- a/src/scamcheck/reference.py
+++ b/src/scamcheck/reference.py
@@ -15,6 +15,8 @@ from typing import Annotated, Any
 
 from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
 
+from scamcheck.schemas import ID_MAX_LENGTH
+
 REFERENCE_DIR_ENV = "SCAMCHECK_REFERENCE_DIR"
 _BSB = r"^000[0-9]{3}$"  # only the 000xxx range is allowed in synthetic data
 _ACCOUNT = r"^[0-9]{6,9}$"
@@ -115,7 +117,7 @@ class _Account(_Model):
 
 
 class _CustomerRow(_Model):
-    customer_id: Annotated[str, Field(min_length=1, max_length=64, strict=True)]
+    customer_id: Annotated[str, Field(min_length=1, max_length=ID_MAX_LENGTH, strict=True)]
     tenure_days: Annotated[int, Field(ge=0, strict=True)]
     typical_payment_amount: Annotated[Decimal, Field(gt=0, decimal_places=2)]
     known_payees: list[_Account]
diff --git a/src/scamcheck/schemas.py b/src/scamcheck/schemas.py
index cdfaceb..5779a3f 100644
--- a/src/scamcheck/schemas.py
+++ b/src/scamcheck/schemas.py
@@ -17,12 +17,15 @@ from pydantic import (
     Field,
     StrictBool,
     ValidationError,
+    ValidationInfo,
+    field_validator,
 )
+from pydantic_core import PydanticCustomError
 
-# TODO: move to config/policy.toml once the policy loader exists.
-MAX_AMOUNT = Decimal("1000000")
+# Maximum length of identifier fields (request_id, customer_id).
+ID_MAX_LENGTH = 64
 
-_Id = Annotated[str, Field(min_length=1, max_length=64, strict=True)]
+_Id = Annotated[str, Field(min_length=1, max_length=ID_MAX_LENGTH, strict=True)]
 
 
 class _Strict(BaseModel):
@@ -45,12 +48,22 @@ class PaymentRequest(_Strict):
     request_id: _Id
     timestamp: AwareDatetime
     customer_id: _Id
-    amount: Annotated[Decimal, Field(gt=0, le=MAX_AMOUNT, decimal_places=2)]
+    amount: Annotated[Decimal, Field(gt=0, decimal_places=2)]
     currency: Literal["AUD"]
     payee: Payee
     channel: Literal["mobile", "web", "branch"]
     session: Session
 
+    @field_validator("amount")
+    @classmethod
+    def _within_max_amount(cls, value: Decimal, info: ValidationInfo) -> Decimal:
+        # The ceiling comes from policy and is supplied by validate_request via the context.
+        limit = (info.context or {}).get("max_amount")
+        if limit is not None and value > limit:
+            # Error type matches pydantic's own so it maps to AMOUNT_TOO_LARGE.
+            raise PydanticCustomError("less_than_equal", "Amount exceeds the maximum allowed.")
+        return value
+
 
 class Decision(StrEnum):
     ALLOW = "ALLOW"
@@ -97,8 +110,8 @@ _MESSAGES: dict[str, str] = {
     "AMOUNT_TOO_LARGE": "Amount exceeds the maximum allowed.",
     "AMOUNT_TOO_PRECISE": "Amount must have at most 2 decimal places.",
     "AMOUNT_INVALID": "Amount is not a valid finite decimal number.",
-    "INVALID_REQUEST_ID": "request_id must be a string of 1-64 characters.",
-    "INVALID_CUSTOMER_ID": "customer_id must be a string of 1-64 characters.",
+    "INVALID_REQUEST_ID": f"request_id must be a string of 1-{ID_MAX_LENGTH} characters.",
+    "INVALID_CUSTOMER_ID": f"customer_id must be a string of 1-{ID_MAX_LENGTH} characters.",
     "UNSUPPORTED_CURRENCY": "Only AUD is supported.",
     "INVALID_CHANNEL": "channel must be one of mobile, web, branch.",
     "INVALID_PAYEE": "payee must be an object.",
@@ -162,12 +175,17 @@ def _issues_from(exc: ValidationError) -> list[ValidationIssue]:
     return sorted(issues, key=lambda i: (i.field, i.code))
 
 
-def validate_request(raw: dict[str, Any]) -> PaymentRequest | list[ValidationIssue]:
-    """Validate raw input. Never raises; returns a request or a non-empty list of issues."""
+def validate_request(
+    raw: dict[str, Any], max_amount: Decimal
+) -> PaymentRequest | list[ValidationIssue]:
+    """Validate raw input. Never raises; returns a request or a non-empty list of issues.
+
+    ``max_amount`` is the policy ceiling (``Policy.max_amount``).
+    """
     if not isinstance(raw, dict):
         return [_issue("INVALID_REQUEST", "")]
     try:
-        return PaymentRequest.model_validate(raw)
+        return PaymentRequest.model_validate(raw, context={"max_amount": max_amount})
     except ValidationError as exc:
         return _issues_from(exc) or [_issue("INVALID_REQUEST", "")]
     except Exception:  # contract: validation must never raise
host:scam-payment-risk-check user$ grep -rn "tomllib\|policy.toml\|def load" src/scamcheck/
src/scamcheck/signals.py:13:# TODO: move to config/policy.toml once the policy loader exists.
src/scamcheck/policy.py:1:"""Load and validate config/policy.toml."""
src/scamcheck/policy.py:6:import tomllib
src/scamcheck/policy.py:48:    return Path(__file__).resolve().parents[2] / "config" / "policy.toml"
src/scamcheck/policy.py:51:def load_policy(path: Path | None = None) -> Policy:
src/scamcheck/policy.py:59:        raw = tomllib.loads(text, parse_float=Decimal)
src/scamcheck/policy.py:60:    except (tomllib.TOMLDecodeError, ValueError) as exc:
Binary file src/scamcheck/__pycache__/policy.cpython-312.pyc matches
src/scamcheck/reference.py:192:def load_reference(paths: ReferencePaths | None = None) -> ReferenceData:
host:scam-payment-risk-check user$ .venv/bin/python -c "from scamcheck.rules import load_policy; load_policy('config/does-not-exist.toml')"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ImportError: cannot import name 'load_policy' from 'scamcheck.rules' (/Users/user/MyApps/scam-payment-risk-check/src/scamcheck/rules.py)
host:scam-payment-risk-check user$ git log --reverse --format="%cd" --date=format:"%H:%M" | head -1
15:35
host:scam-payment-risk-check user$ ls scripts/ sample-data/
sample-data/:
README.md	reference

scripts/:
__pycache__			generate_reference_data.py	generate_training_data.py	README.md
host:scam-payment-risk-check user$ grep -n "scenario\|seed\|split" scripts/generate_training_data.py scripts/train_model.py
scripts/generate_training_data.py:1:"""Generate the SYNTHETIC training set for the risk model (seeded, deterministic).
scripts/generate_training_data.py:5:Population: 5000 payments, seed 42. About 15% are scams (label 1), the rest genuine (label 0).
scripts/generate_training_data.py:6:This training set is separate from the evaluation scenarios, which are written by hand later.
scripts/generate_training_data.py:28:    python scripts/generate_training_data.py [--out PATH] [--seed N] [--count N]
scripts/generate_training_data.py:49:    "scripts/generate_training_data.py (seed {seed}, {count} rows). Do not edit by hand."
scripts/generate_training_data.py:169:def generate_rows(count: int = COUNT, seed: int = SEED) -> list[dict[str, object]]:
scripts/generate_training_data.py:170:    rng = random.Random(seed)
scripts/generate_training_data.py:182:def render(rows: list[dict[str, object]], seed: int = SEED) -> str:
scripts/generate_training_data.py:184:    buffer.write(NOTE.format(seed=seed, count=len(rows)) + "\n")
scripts/generate_training_data.py:191:def generate(out: Path, count: int = COUNT, seed: int = SEED) -> Path:
scripts/generate_training_data.py:193:    out.write_text(render(generate_rows(count, seed), seed), encoding="utf-8")
scripts/generate_training_data.py:200:    parser.add_argument("--seed", type=int, default=SEED)
scripts/generate_training_data.py:203:    print(f"wrote {generate(args.out, args.count, args.seed)}")
grep: scripts/train_model.py: No such file or directory
host:scam-payment-risk-check user$ grep -n "scenario\|seed\|split" scripts/generate_training_data.py scripts/train_model.py
scripts/generate_training_data.py:1:"""Generate the SYNTHETIC training set for the risk model (seeded, deterministic).
scripts/generate_training_data.py:5:Population: 5000 payments, seed 42. About 15% are scams (label 1), the rest genuine (label 0).
scripts/generate_training_data.py:6:This training set is separate from the evaluation scenarios, which are written by hand later.
scripts/generate_training_data.py:28:    python scripts/generate_training_data.py [--out PATH] [--seed N] [--count N]
scripts/generate_training_data.py:49:    "scripts/generate_training_data.py (seed {seed}, {count} rows). Do not edit by hand."
scripts/generate_training_data.py:169:def generate_rows(count: int = COUNT, seed: int = SEED) -> list[dict[str, object]]:
scripts/generate_training_data.py:170:    rng = random.Random(seed)
scripts/generate_training_data.py:182:def render(rows: list[dict[str, object]], seed: int = SEED) -> str:
scripts/generate_training_data.py:184:    buffer.write(NOTE.format(seed=seed, count=len(rows)) + "\n")
scripts/generate_training_data.py:191:def generate(out: Path, count: int = COUNT, seed: int = SEED) -> Path:
scripts/generate_training_data.py:193:    out.write_text(render(generate_rows(count, seed), seed), encoding="utf-8")
scripts/generate_training_data.py:200:    parser.add_argument("--seed", type=int, default=SEED)
scripts/generate_training_data.py:203:    print(f"wrote {generate(args.out, args.count, args.seed)}")
scripts/train_model.py:3:Reads the SYNTHETIC training set, holds out 20% (seeded shuffle), fits on the rest, and writes:
scripts/train_model.py:9:PR-AUC is approximated by average precision on the held-out split.
scripts/train_model.py:71:def split_indices(
scripts/train_model.py:72:    n: int, seed: int = SEED, held_out: float = HELD_OUT_SHARE
scripts/train_model.py:75:    random.Random(seed).shuffle(order)
scripts/train_model.py:163:    train_idx, held_idx = split_indices(len(x))
host:scam-payment-risk-check user$ .venv/bin/python - <<'EOF'
> import json
> m = json.load(open("models/risk_model_v1.json"))
> print("model_version:", m.get("model_version"))
> print("\nFEATURE                     WEIGHT")
> for f, c in zip(m["features"], m["coefficients"]):
>     print(f"{f:<27} {c:+.3f}")
> print(f"{'intercept':<27} {m['intercept']:+.3f}")
> print("\nmetrics:", json.dumps(m.get("metrics"), indent=1))
> EOF
model_version: risk_model_v1

FEATURE                     WEIGHT
new_payee                   +2.221
log_amount_ratio            +1.175
young_account               +1.759
name_mismatch               +2.061
on_active_call              +1.808
remote_access_detected      +2.096
new_device                  +0.635
intercept                   -4.277

metrics: {
 "train_size": 4000,
 "held_out_size": 1000,
 "held_out_positives": 150,
 "pr_auc_approx": 0.9127,
 "at_0.50": {
  "threshold": 0.5,
  "precision": 0.8626,
  "recall": 0.7533
 },
 "at_score_warn": {
  "threshold": 0.35,
  "precision": 0.7987,
  "recall": 0.7933
 },
 "at_score_hold": {
  "threshold": 0.7,
  "precision": 0.9794,
  "recall": 0.6333
 }
}
host:scam-payment-risk-check user$ ls models/
README.md		risk_model_v1.json	risk_model_v1.sha256
host:scam-payment-risk-check user$ shasum -a 256 models/risk_model_v1.json
cb2e94f956bb04a56ff1935d4ad35f761e1789c9d97868c153b8d2ec25670908  models/risk_model_v1.json
host:scam-payment-risk-check user$ less models/risk_model_v1.sha256 
host:scam-payment-risk-check user$ grep -n "exp\|def " src/scamcheck/model.py
5:(``ModelRuntime.health()`` explains why) instead of raising at request time.
73:    def __init__(self, path: Path, code: ModelErrorCode, message: str) -> None:
80:def sha256_hex(data: bytes) -> str:
84:def extract_features(signals: Signals, young_account_days: int) -> list[float]:
100:def sigmoid(z: float) -> float:
102:        return 1.0 / (1.0 + math.exp(-z))
103:    e = math.exp(z)
120:    def score(self, signals: Signals) -> ModelScore:
144:def default_model_path() -> Path:
151:def _read_bytes(path: Path, what: str) -> bytes:
158:def _verify_checksum(path: Path, data: bytes) -> None:
161:    expected = text[0].lower() if text else ""
162:    if not hmac.compare_digest(expected, sha256_hex(data)):
166:def _parse(path: Path, data: bytes) -> dict[str, object]:
176:def load_model(path: Path | str | None = None) -> RiskModel:
212:    def health(self) -> ModelHealth:
218:    def from_path(cls, path: Path | str | None = None) -> ModelRuntime:
226:            code, detail = "MODEL_LOAD_ERROR", "unexpected error while loading the model"
234:def default_runtime() -> ModelRuntime:
host:scam-payment-risk-check user$ .venv/bin/python -c "from scamcheck.model import _sigmoid as s; print(s(1000), s(-1000), s(0))"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ImportError: cannot import name '_sigmoid' from 'scamcheck.model' (/Users/user/MyApps/scam-payment-risk-check/src/scamcheck/model.py). Did you mean: 'sigmoid'?
host:scam-payment-risk-check user$ less src/scamcheck/model.py 
host:scam-payment-risk-check user$ .venv/bin/python -c "from scamcheck.model import sigmoid as s; print(s(1000), s(-1000), s(0))"
1.0 0.0 0.5
host:scam-payment-risk-check user$ grep -n -i "degrad\|fail_safe\|rules_only\|health" src/scamcheck/engine.py src/scamcheck/model.py
src/scamcheck/engine.py:4:DEGRADED_RULES_ONLY mode (model unavailable): rules only, plus a fail-safe HOLD for any risk
src/scamcheck/engine.py:79:def _fail_safe(meta: _Meta, code: str, detail: str, policy_version: str) -> DecisionResponse:
src/scamcheck/engine.py:107:def _degraded_outcome(signals: Signals, amount: Decimal, policy: Policy) -> _ModelOutcome:
src/scamcheck/engine.py:109:    outcome = _ModelOutcome(mode=Mode.DEGRADED_RULES_ONLY)
src/scamcheck/engine.py:114:                code="DEGRADED_FAILSAFE_HOLD",
src/scamcheck/engine.py:126:        return _degraded_outcome(signals, amount, policy)
src/scamcheck/engine.py:206:        return _fail_safe(
src/scamcheck/engine.py:210:        return _fail_safe(
src/scamcheck/engine.py:217:        return _fail_safe(
src/scamcheck/engine.py:224:        return _fail_safe(
src/scamcheck/model.py:4:feature list must equal ``FEATURES`` exactly. Any problem puts the service in degraded mode
src/scamcheck/model.py:5:(``ModelRuntime.health()`` explains why) instead of raising at request time.
src/scamcheck/model.py:200:class ModelHealth:
src/scamcheck/model.py:201:    status: Literal["ok", "degraded"]
src/scamcheck/model.py:202:    reason: str | None  # error code when degraded
src/scamcheck/model.py:212:    def health(self) -> ModelHealth:
src/scamcheck/model.py:214:            return ModelHealth("ok", None)
src/scamcheck/model.py:215:        return ModelHealth("degraded", self.reason or "MODEL_LOAD_ERROR")
src/scamcheck/model.py:219:        """Load the model; on any failure return a degraded runtime and log it once."""
src/scamcheck/model.py:228:            "Risk model unavailable (%s: %s); running in DEGRADED_RULES_ONLY mode", code, detail
src/scamcheck/model.py:235:    """The process-wide runtime, loaded once (so a degrade is logged once)."""
host:scam-payment-risk-check user$ cat > /tmp/degrade_check.py <<'EOF'
> import json, re, tomllib, pathlib
> from scamcheck.engine import assess
> ref = pathlib.Path("sample-data/reference")
> pol = tomllib.load(open("config/policy.toml", "rb"))
> flat = lambda d: {k: v for k, v in pol.items()} | {k: v for s in pol.values() if isinstance(s, dict) for k, v in s.items()}
> p = flat(pol)
> cust_text = (ref / "customers.json").read_text(); cust = json.loads(cust_text)
> def find(o, key):
>     if isinstance(o, dict):
>         if key in o: yield o
>         for v in o.values(): yield from find(v, key)
>     elif isinstance(o, list):
>         for v in o: yield from find(v, key)
> c = next(find(cust, "customer_id"))
> known = {(k["bsb"], k["account_number"]) for k in c.get("known_payees", [])}
> mules = set(re.findall(r'"(\d{6})"\s*,\s*"account_number"\s*:\s*"(\d+)"', (ref / "mule_accounts.json").read_text()))
> keys = re.findall(r'"(\d{6})-(\d{6,9})"', (ref / "payees.json").read_text())
> bsb, acct = next(k for k in keys if k not in known and k not in mules)
> amount = min(p["abstain_amount"] + 500, p["high_value_amount"] - 1)
> raw = {"request_id": "degrade-check", "timestamp": "2026-11-10T09:15:00+11:00",
>        "customer_id": c["customer_id"], "amount": str(amount), "currency": "AUD",
>        "payee": {"name": "Test Payee", "bsb": bsb, "account_number": acct}, "channel": "mobile",
>        "session": {"on_active_call": True, "remote_access_detected": False, "new_device": False}}
> r = assess(raw)
> print("decision:", r.decision, "| mode:", r.mode, "| score:", r.risk_score)
> print("reasons:", [x.code for x in r.reasons])
> EOF
host:scam-payment-risk-check user$ .venv/bin/python /tmp/degrade_check.py
decision: HOLD | mode: NORMAL | score: 0.9892
reasons: ['R04_PAYEE_NAME_MISMATCH', 'R05_UNUSUAL_AMOUNT', 'M_AMOUNT_ABOVE_TYPICAL', 'M_NEW_PAYEE']
host:scam-payment-risk-check user$ echo " " >> models/risk_model_v1.json
host:scam-payment-risk-check user$ .venv/bin/python /tmp/degrade_check.py
Risk model unavailable (MODEL_INTEGRITY_FAILED: checksum does not match the artifact); running in DEGRADED_RULES_ONLY mode
decision: HOLD | mode: DEGRADED_RULES_ONLY | score: None
reasons: ['R04_PAYEE_NAME_MISMATCH', 'R05_UNUSUAL_AMOUNT', 'DEGRADED_FAILSAFE_HOLD']
host:scam-payment-risk-check user$ git checkout models/risk_model_v1.json
error: pathspec 'models/risk_model_v1.json' did not match any file(s) known to git
host:scam-payment-risk-check user$ cat > /tmp/scenarios_review.py <<'EOF'
> import json
> from scamcheck.engine import assess
> rows = [json.loads(l) for l in open("sample-data/scenarios.jsonl") if l.strip()]
> print(f"{len(rows)} scenarios\n")
> for s in rows:
>     r = s.get("request", {})
>     sess = r.get("session", {}) if isinstance(r, dict) else {}
>     try:
>         res = assess(r); actual = str(getattr(res.decision, "value", res.decision))
>         reasons = ",".join(x.code for x in res.reasons)
>     except Exception as e:
>         actual, reasons = "ERROR", repr(e)[:60]
>     exp = s.get("expected_decision")
>     exp = "/".join(exp) if isinstance(exp, list) else str(exp)
>     ok = "ok " if actual in exp.split("/") else "<<<"
>     flags = "".join(k for k, v in (("C", sess.get("on_active_call")), ("R", sess.get("remote_access_detected")), ("D", sess.get("new_device"))) if v)
>     print(f"{ok} {s['id']:<10} {s.get('typology',''):<16} scam={str(s.get('is_scam')):<5} must_hold={str(s.get('must_hold')):<5} "
>           f"amt={str(r.get('amount','-')):>9} flags={flags or '-':<3} expected={exp:<10} actual={actual:<7} {reasons}")
>     print(f"      {s.get('description','')}")
> EOF
host:scam-payment-risk-check user$ .venv/bin/python /tmp/scenarios_review.py
38 scenarios

ok  S01        impersonation    scam=True  must_hold=True  amt=  4800.00 flags=CD  expected=HOLD       actual=HOLD    R03_ON_CALL_NEW_PAYEE_HIGH_VALUE,R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Caller posing as the bank's fraud team; high-value payment to a new payee while on the call, from a new device.
ok  S02        impersonation    scam=True  must_hold=False amt=  1900.00 flags=C   expected=WARN/HOLD  actual=HOLD    R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Fake police officer on the phone; mid-value 'safe account' payment far above the customer's usual amount.
ok  S03        impersonation    scam=True  must_hold=True  amt=  2500.00 flags=CR  expected=HOLD       actual=HOLD    R02_REMOTE_ACCESS_NEW_PAYEE,M_NEW_PAYEE,M_REMOTE_ACCESS
      Impersonator on the phone also has the customer install a remote-access tool; new payee.
ok  S04        impersonation    scam=True  must_hold=True  amt=  3200.00 flags=C   expected=HOLD       actual=HOLD    R03_ON_CALL_NEW_PAYEE_HIGH_VALUE,R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Government-agency impersonation; high-value payment to a new payee during the call.
ok  S05        remote_access    scam=True  must_hold=True  amt=   900.00 flags=R   expected=HOLD       actual=HOLD    R02_REMOTE_ACCESS_NEW_PAYEE,M_NEW_PAYEE,M_REMOTE_ACCESS
      Tech-support scam: remote-access tool detected while paying a new payee.
ok  S06        remote_access    scam=True  must_hold=True  amt=  1500.00 flags=CR  expected=HOLD       actual=HOLD    R02_REMOTE_ACCESS_NEW_PAYEE,R05_UNUSUAL_AMOUNT,M_NEW_PAYEE,M_REMOTE_ACCESS
      Refund scam: remote access plus an active call, payment to a new payee.
ok  S07        mule_payee       scam=True  must_hold=True  amt=   600.00 flags=-   expected=HOLD       actual=HOLD    R01_MULE_PAYEE,R06_YOUNG_PAYEE_ACCOUNT,M_NEW_PAYEE,M_YOUNG_PAYEE_ACCOUNT
      Payment to an account on the mule list.
ok  S08        mule_payee       scam=True  must_hold=True  amt=  2000.00 flags=-   expected=HOLD       actual=HOLD    R01_MULE_PAYEE,R04_PAYEE_NAME_MISMATCH,R06_YOUNG_PAYEE_ACCOUNT,M_NEW_PAYEE,M_NAME_MISMATCH
      Mule account with a made-up payee name that does not match the account.
ok  S09        mule_payee       scam=True  must_hold=True  amt=   300.00 flags=-   expected=HOLD       actual=HOLD    R01_MULE_PAYEE
      Mule-listed account that is absent from the payee reference data.
ok  S10        investment       scam=True  must_hold=True  amt=  8000.00 flags=-   expected=HOLD       actual=HOLD    R05_UNUSUAL_AMOUNT,R06_YOUNG_PAYEE_ACCOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Fake investment platform: very large payment (many times typical) to a days-old account.
ok  S11        investment       scam=True  must_hold=True  amt=  4000.00 flags=-   expected=HOLD       actual=HOLD    R05_UNUSUAL_AMOUNT,R06_YOUNG_PAYEE_ACCOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Crypto 'trading' scam: large payment to a recently opened account.
ok  S12        investment       scam=True  must_hold=False amt=  1200.00 flags=-   expected=WARN/HOLD  actual=HOLD    R05_UNUSUAL_AMOUNT,R06_YOUNG_PAYEE_ACCOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Newly joined customer sends a payment about twenty times their typical amount to a days-old investment account.
ok  S13        investment       scam=True  must_hold=False amt=   600.00 flags=-   expected=WARN/HOLD  actual=WARN    R06_YOUNG_PAYEE_ACCOUNT,M_NEW_PAYEE,M_YOUNG_PAYEE_ACCOUNT
      'Trial deposit' to a recently opened crypto account, slightly above the usual amount.
ok  S14        invoice_redirection scam=True  must_hold=True  amt=  6500.00 flags=-   expected=HOLD       actual=HOLD    R04_PAYEE_NAME_MISMATCH,R05_UNUSUAL_AMOUNT,M_NEW_PAYEE,M_NAME_MISMATCH
      Customer's usual tradesperson 'changes bank details'; the new account is held in a different name; high-value invoice.
ok  S15        invoice_redirection scam=True  must_hold=False amt=  2400.00 flags=-   expected=WARN/HOLD  actual=HOLD    R04_PAYEE_NAME_MISMATCH,R05_UNUSUAL_AMOUNT,M_NEW_PAYEE,M_NAME_MISMATCH
      Accountant's invoice redirected to a personal account in a different name; mid-value.
ok  S16        invoice_redirection scam=True  must_hold=False amt=  5000.00 flags=-   expected=WARN/HOLD  actual=WARN    M_NEW_PAYEE,M_AMOUNT_ABOVE_TYPICAL
      Redirected invoice to an account whose name closely resembles the real supplier; amount several times usual.
ok  S17        romance          scam=True  must_hold=False amt=  1500.00 flags=D   expected=WARN/HOLD  actual=HOLD    R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Online partner asks for an urgent payment; new payee, amount many times typical, new device.
ok  S18        romance          scam=True  must_hold=False amt=   900.00 flags=-   expected=WARN/HOLD  actual=HOLD    R04_PAYEE_NAME_MISMATCH,M_NEW_PAYEE,M_NAME_MISMATCH
      Gift money to an overseas 'friend'; account name differs from the name given.
ok  G01        genuine_rent     scam=False must_hold=False amt=  1200.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Monthly rent to the long-standing property manager, usual amount.
ok  G02        genuine_routine  scam=False must_hold=False amt=  2000.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Regular payment to a known landscaper at the usual amount.
ok  G03        genuine_house_deposit scam=False must_hold=False amt= 20000.00 flags=-   expected=ALLOW/WARN actual=WARN    R05_UNUSUAL_AMOUNT
      House deposit to the customer's long-established accountant/settlement payee; far above typical amount.
<<< G04        genuine_large_purchase scam=False must_hold=False amt=  4000.00 flags=-   expected=ALLOW/WARN actual=HOLD    R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Car purchase from an established dealer the customer has not paid before; large versus typical amount.
ok  G05        genuine_small_new_payee scam=False must_hold=False amt=    60.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Small payment to a new payee (pet care) well below the typical amount.
ok  G06        genuine_small_new_payee scam=False must_hold=False amt=   400.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      New tutoring provider paid about the usual amount.
ok  G07        genuine_routine  scam=False must_hold=False amt=    95.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Regular energy bill at the usual amount.
ok  G08        genuine_routine  scam=False must_hold=False amt=   150.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Regular payment to a known person, name typed with an initial only.
ok  G09        genuine_routine  scam=False must_hold=False amt=    85.00 flags=-   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Known payee with a small typo in the name.
ok  G10        genuine_new_payee scam=False must_hold=False amt=   600.00 flags=D   expected=ALLOW/WARN actual=WARN    M_NEW_PAYEE,M_AMOUNT_ABOVE_TYPICAL
      New travel provider on a freshly bought phone; modest amount.
ok  G11        genuine_routine  scam=False must_hold=False amt=   420.00 flags=C   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Customer on a call with a friend pays a known payee their usual amount.
ok  G12        genuine_new_payee scam=False must_hold=False amt=  3000.00 flags=-   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Electrician paid for work done; new payee, established business, modest amount versus typical.
ok  M01        missing_data     scam=None  must_hold=True  amt=  2500.00 flags=-   expected=HOLD       actual=HOLD    ABSTAIN_INSUFFICIENT_DATA
      Customer not in reference data; payment at or above the abstain amount.
ok  M02        missing_data     scam=None  must_hold=True  amt=  1500.00 flags=-   expected=HOLD       actual=HOLD    ABSTAIN_INSUFFICIENT_DATA
      Payee account not in reference data; payment above the abstain amount.
ok  M03        missing_data     scam=None  must_hold=False amt=    50.00 flags=-   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Customer not in reference data but the payment is well below the abstain amount.
ok  V01        invalid_request  scam=None  must_hold=False amt=   -20.00 flags=-   expected=REJECT     actual=REJECT  AMOUNT_NOT_POSITIVE
      Negative amount.
ok  V02        invalid_request  scam=None  must_hold=False amt=   100.00 flags=-   expected=REJECT     actual=REJECT  INVALID_BSB
      BSB with five digits.
ok  V03        invalid_request  scam=None  must_hold=False amt=   100.00 flags=-   expected=REJECT     actual=REJECT  NAIVE_TIMESTAMP
      Timestamp without a timezone.
ok  V04        invalid_request  scam=None  must_hold=False amt=   100.00 flags=-   expected=REJECT     actual=REJECT  UNSUPPORTED_CURRENCY,UNKNOWN_FIELD
      Unsupported currency and an unknown field.
Traceback (most recent call last):
  File "/tmp/scenarios_review.py", line 18, in <module>
    f"amt={str(r.get('amount','-')):>9} flags={flags or '-':<3} expected={exp:<10} actual={actual:<7} {reasons}")
               ^^^^^
AttributeError: 'str' object has no attribute 'get'
host:scam-payment-risk-check user$ git diff HEAD --stat
 Makefile                |  2 +-
 config/policy.toml      |  7 +++++++
 evidence/decisions.md   |  7 +++++++
 evidence/design.md      |  5 +++++
 evidence/operate.md     |  4 ++++
 evidence/verify.md      |  5 +++++
 src/scamcheck/policy.py |  8 ++++++++
 tests/test_policy.py    | 12 ++++++++++++
 tests/test_rules.py     |  3 ++-
 9 files changed, 51 insertions(+), 2 deletions(-)
host:scam-payment-risk-check user$ head -40 evidence/eval-report.md
# Evaluation report

SYNTHETIC scenarios only (`sample-data/scenarios.jsonl`).
Generated by `make eval`; do not edit.

- Policy version: `2026.11.1`
- Model version: `risk_model_v1` (mode `NORMAL`)
- Overall: **PASS**

## Gate results

| Gate | Result | Detail |
|---|---|---|
| 1. All must-hold scenarios are HOLD | PASS | 13/13 must-hold scenarios held |
| 2. Scams caught (WARN or HOLD) | PASS | 18/18 scams warned or held (100.0%); need >= 90% |
| 3. Genuine payments held within budget | PASS | 1/12 genuine scenarios held (8.3%); allow <= 10%. Held: G04 -> HOLD [R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE] |
| 4. Every non-REJECT decision has a reason | PASS | 33/33 non-REJECT decisions have a reason |
| 5. Two runs give identical decisions | PASS | 38/38 scenarios identical across two runs |
| 6. Must-hold scenarios still HOLD with a tampered model | PASS | tamper detected (MODEL_INTEGRITY_FAILED); 13/13 must-hold scenarios held in DEGRADED_RULES_ONLY; degrade warnings logged: 1 |

## Summary metrics

| Metric | Value |
|---|---|
| Scenarios | 38 |
| Scam scenarios warned or held | 18/18 |
| Genuine scenarios held | 1/12 |
| Unlabelled (missing data / invalid), excluded from the two rates | 8 |
| Must-hold scenarios held | 13/13 |
| Scenarios matching their expected decision | 37/38 |
| Scenarios passing (decision and expected reason codes) | 37/38 |

## Scenarios

| ID | Typology | Scam? | Expected | Actual | Score | Reason codes | Result |
|---|---|---|---|---|---|---|---|
| S01 | impersonation | yes | HOLD (must hold) | HOLD | 0.9626 | R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S02 | impersonation | yes | WARN/HOLD | HOLD | 0.9634 | R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S03 | impersonation | yes | HOLD (must hold) | HOLD | 0.9376 | R02_REMOTE_ACCESS_NEW_PAYEE, M_NEW_PAYEE, M_REMOTE_ACCESS | PASS |
| S04 | impersonation | yes | HOLD (must hold) | HOLD | 0.9821 | R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
host:scam-payment-risk-check user$ head -40 evidence/eval-report.md
# Evaluation report

SYNTHETIC scenarios only (`sample-data/scenarios.jsonl`).
Generated by `make eval`; do not edit.

- Policy version: `2026.11.1`
- Model version: `risk_model_v1` (mode `NORMAL`)
- Overall: **FAIL**

## Gate results

| Gate | Result | Detail |
|---|---|---|
| 1. All must-hold scenarios are HOLD | PASS | 13/13 must-hold scenarios held |
| 2. Scams caught (WARN or HOLD) | FAIL | 18/21 scams warned or held (85.7%); need >= 90%. Missed: X01 -> ALLOW [NO_RISK_SIGNALS]; X02 -> ALLOW [NO_RISK_SIGNALS]; X03 -> ALLOW [NO_RISK_SIGNALS] |
| 3. Genuine payments held within budget | FAIL | 3/14 genuine scenarios held (21.4%); allow <= 10%. Held: G04 -> HOLD [R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE]; X04 -> HOLD [R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, M_NEW_PAYEE, M_ON_ACTIVE_CALL]; X05 -> HOLD [R04_PAYEE_NAME_MISMATCH, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE] |
| 4. Every non-REJECT decision has a reason | PASS | 38/38 non-REJECT decisions have a reason |
| 5. Two runs give identical decisions | PASS | 43/43 scenarios identical across two runs |
| 6. Must-hold scenarios still HOLD with a tampered model | PASS | tamper detected (MODEL_INTEGRITY_FAILED); 13/13 must-hold scenarios held in DEGRADED_RULES_ONLY; degrade warnings logged: 1 |

## Summary metrics

| Metric | Value |
|---|---|
| Scenarios | 43 |
| Scam scenarios warned or held | 18/21 |
| Genuine scenarios held | 3/14 |
| Unlabelled (missing data / invalid), excluded from the two rates | 8 |
| Must-hold scenarios held | 13/13 |
| Scenarios matching their expected decision | 37/43 |
| Scenarios passing (decision and expected reason codes) | 37/43 |

## Scenarios

| ID | Typology | Scam? | Expected | Actual | Score | Reason codes | Result |
|---|---|---|---|---|---|---|---|
| S01 | impersonation | yes | HOLD (must hold) | HOLD | 0.9626 | R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S02 | impersonation | yes | WARN/HOLD | HOLD | 0.9634 | R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S03 | impersonation | yes | HOLD (must hold) | HOLD | 0.9376 | R02_REMOTE_ACCESS_NEW_PAYEE, M_NEW_PAYEE, M_REMOTE_ACCESS | PASS |
| S04 | impersonation | yes | HOLD (must hold) | HOLD | 0.9821 | R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
host:scam-payment-risk-check user$ .venv/bin/python /tmp/scenarios_review.py
39 scenarios

ok  S01        impersonation    scam=True  must_hold=True  amt=  4800.00 flags=CD  expected=HOLD       actual=HOLD    R03_ON_CALL_NEW_PAYEE_HIGH_VALUE,R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Caller posing as the bank's fraud team; high-value payment to a new payee while on the call, from a new device.
ok  S02        impersonation    scam=True  must_hold=False amt=  1900.00 flags=C   expected=WARN/HOLD  actual=HOLD    R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Fake police officer on the phone; mid-value 'safe account' payment far above the customer's usual amount.
ok  S03        impersonation    scam=True  must_hold=True  amt=  2500.00 flags=CR  expected=HOLD       actual=HOLD    R02_REMOTE_ACCESS_NEW_PAYEE,M_NEW_PAYEE,M_REMOTE_ACCESS
      Impersonator on the phone also has the customer install a remote-access tool; new payee.
ok  S04        impersonation    scam=True  must_hold=True  amt=  3200.00 flags=C   expected=HOLD       actual=HOLD    R03_ON_CALL_NEW_PAYEE_HIGH_VALUE,R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Government-agency impersonation; high-value payment to a new payee during the call.
ok  S05        remote_access    scam=True  must_hold=True  amt=   900.00 flags=R   expected=HOLD       actual=HOLD    R02_REMOTE_ACCESS_NEW_PAYEE,M_NEW_PAYEE,M_REMOTE_ACCESS
      Tech-support scam: remote-access tool detected while paying a new payee.
ok  S06        remote_access    scam=True  must_hold=True  amt=  1500.00 flags=CR  expected=HOLD       actual=HOLD    R02_REMOTE_ACCESS_NEW_PAYEE,R05_UNUSUAL_AMOUNT,M_NEW_PAYEE,M_REMOTE_ACCESS
      Refund scam: remote access plus an active call, payment to a new payee.
ok  S07        mule_payee       scam=True  must_hold=True  amt=   600.00 flags=-   expected=HOLD       actual=HOLD    R01_MULE_PAYEE,R06_YOUNG_PAYEE_ACCOUNT,M_NEW_PAYEE,M_YOUNG_PAYEE_ACCOUNT
      Payment to an account on the mule list.
ok  S08        mule_payee       scam=True  must_hold=True  amt=  2000.00 flags=-   expected=HOLD       actual=HOLD    R01_MULE_PAYEE,R04_PAYEE_NAME_MISMATCH,R06_YOUNG_PAYEE_ACCOUNT,M_NEW_PAYEE,M_NAME_MISMATCH
      Mule account with a made-up payee name that does not match the account.
ok  S09        mule_payee       scam=True  must_hold=True  amt=   300.00 flags=-   expected=HOLD       actual=HOLD    R01_MULE_PAYEE
      Mule-listed account that is absent from the payee reference data.
ok  S10        investment       scam=True  must_hold=True  amt=  8000.00 flags=-   expected=HOLD       actual=HOLD    R05_UNUSUAL_AMOUNT,R06_YOUNG_PAYEE_ACCOUNT,R07_YOUNG_PAYEE_HIGH_VALUE,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Fake investment platform: very large payment (many times typical) to a days-old account.
ok  S11        investment       scam=True  must_hold=True  amt=  4000.00 flags=-   expected=HOLD       actual=HOLD    R05_UNUSUAL_AMOUNT,R06_YOUNG_PAYEE_ACCOUNT,R07_YOUNG_PAYEE_HIGH_VALUE,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Crypto 'trading' scam: large payment to a recently opened account.
ok  S12        investment       scam=True  must_hold=False amt=  1200.00 flags=-   expected=WARN/HOLD  actual=HOLD    R05_UNUSUAL_AMOUNT,R06_YOUNG_PAYEE_ACCOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Newly joined customer sends a payment about twenty times their typical amount to a days-old investment account.
ok  S13        investment       scam=True  must_hold=False amt=   600.00 flags=-   expected=WARN/HOLD  actual=WARN    R06_YOUNG_PAYEE_ACCOUNT,M_NEW_PAYEE,M_YOUNG_PAYEE_ACCOUNT
      'Trial deposit' to a recently opened crypto account, slightly above the usual amount.
ok  S14        invoice_redirection scam=True  must_hold=True  amt=  6500.00 flags=-   expected=HOLD       actual=HOLD    R04_PAYEE_NAME_MISMATCH,R05_UNUSUAL_AMOUNT,M_NEW_PAYEE,M_NAME_MISMATCH
      Customer's usual tradesperson 'changes bank details'; the new account is held in a different name; high-value invoice.
ok  S15        invoice_redirection scam=True  must_hold=False amt=  2400.00 flags=-   expected=WARN/HOLD  actual=HOLD    R04_PAYEE_NAME_MISMATCH,R05_UNUSUAL_AMOUNT,M_NEW_PAYEE,M_NAME_MISMATCH
      Accountant's invoice redirected to a personal account in a different name; mid-value.
ok  S16        invoice_redirection scam=True  must_hold=False amt=  5000.00 flags=-   expected=WARN/HOLD  actual=WARN    M_NEW_PAYEE,M_AMOUNT_ABOVE_TYPICAL
      Redirected invoice to an account whose name closely resembles the real supplier; amount several times usual.
ok  S17        romance          scam=True  must_hold=False amt=  1500.00 flags=D   expected=WARN/HOLD  actual=HOLD    R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Online partner asks for an urgent payment; new payee, amount many times typical, new device.
ok  S18        romance          scam=True  must_hold=False amt=   900.00 flags=-   expected=WARN/HOLD  actual=HOLD    R04_PAYEE_NAME_MISMATCH,M_NEW_PAYEE,M_NAME_MISMATCH
      Gift money to an overseas 'friend'; account name differs from the name given.
ok  S19        investment       scam=True  must_hold=True  amt=  3500.00 flags=-   expected=HOLD       actual=HOLD    R06_YOUNG_PAYEE_ACCOUNT,R07_YOUNG_PAYEE_HIGH_VALUE,M_NEW_PAYEE,M_YOUNG_PAYEE_ACCOUNT
      Fake investment platform aimed at a high-balance customer: high-value first payment to a days-old account. The customer's usual payments are large, so the amount is not unusual for them and ratio-based signals stay quiet.
ok  G01        genuine_rent     scam=False must_hold=False amt=  1200.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Monthly rent to the long-standing property manager, usual amount.
ok  G02        genuine_routine  scam=False must_hold=False amt=  2000.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Regular payment to a known landscaper at the usual amount.
ok  G03        genuine_house_deposit scam=False must_hold=False amt= 20000.00 flags=-   expected=ALLOW/WARN actual=WARN    R05_UNUSUAL_AMOUNT
      House deposit to the customer's long-established accountant/settlement payee; far above typical amount.
<<< G04        genuine_large_purchase scam=False must_hold=False amt=  4000.00 flags=-   expected=ALLOW/WARN actual=HOLD    R05_UNUSUAL_AMOUNT,M_AMOUNT_ABOVE_TYPICAL,M_NEW_PAYEE
      Car purchase from an established dealer the customer has not paid before; large versus typical amount.
ok  G05        genuine_small_new_payee scam=False must_hold=False amt=    60.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Small payment to a new payee (pet care) well below the typical amount.
ok  G06        genuine_small_new_payee scam=False must_hold=False amt=   400.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      New tutoring provider paid about the usual amount.
ok  G07        genuine_routine  scam=False must_hold=False amt=    95.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Regular energy bill at the usual amount.
ok  G08        genuine_routine  scam=False must_hold=False amt=   150.00 flags=-   expected=ALLOW      actual=ALLOW   NO_RISK_SIGNALS
      Regular payment to a known person, name typed with an initial only.
ok  G09        genuine_routine  scam=False must_hold=False amt=    85.00 flags=-   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Known payee with a small typo in the name.
ok  G10        genuine_new_payee scam=False must_hold=False amt=   600.00 flags=D   expected=ALLOW/WARN actual=WARN    M_NEW_PAYEE,M_AMOUNT_ABOVE_TYPICAL
      New travel provider on a freshly bought phone; modest amount.
ok  G11        genuine_routine  scam=False must_hold=False amt=   420.00 flags=C   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Customer on a call with a friend pays a known payee their usual amount.
ok  G12        genuine_new_payee scam=False must_hold=False amt=  3000.00 flags=-   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Electrician paid for work done; new payee, established business, modest amount versus typical.
ok  M01        missing_data     scam=None  must_hold=True  amt=  2500.00 flags=-   expected=HOLD       actual=HOLD    ABSTAIN_INSUFFICIENT_DATA
      Customer not in reference data; payment at or above the abstain amount.
ok  M02        missing_data     scam=None  must_hold=True  amt=  1500.00 flags=-   expected=HOLD       actual=HOLD    ABSTAIN_INSUFFICIENT_DATA
      Payee account not in reference data; payment above the abstain amount.
ok  M03        missing_data     scam=None  must_hold=False amt=    50.00 flags=-   expected=ALLOW/WARN actual=ALLOW   NO_RISK_SIGNALS
      Customer not in reference data but the payment is well below the abstain amount.
ok  V01        invalid_request  scam=None  must_hold=False amt=   -20.00 flags=-   expected=REJECT     actual=REJECT  AMOUNT_NOT_POSITIVE
      Negative amount.
ok  V02        invalid_request  scam=None  must_hold=False amt=   100.00 flags=-   expected=REJECT     actual=REJECT  INVALID_BSB
      BSB with five digits.
ok  V03        invalid_request  scam=None  must_hold=False amt=   100.00 flags=-   expected=REJECT     actual=REJECT  NAIVE_TIMESTAMP
      Timestamp without a timezone.
ok  V04        invalid_request  scam=None  must_hold=False amt=   100.00 flags=-   expected=REJECT     actual=REJECT  UNSUPPORTED_CURRENCY,UNKNOWN_FIELD
      Unsupported currency and an unknown field.
Traceback (most recent call last):
  File "/tmp/scenarios_review.py", line 18, in <module>
    f"amt={str(r.get('amount','-')):>9} flags={flags or '-':<3} expected={exp:<10} actual={actual:<7} {reasons}")
               ^^^^^
AttributeError: 'str' object has no attribute 'get'
host:scam-payment-risk-check user$ Label changes from my review:
-bash: Label: command not found
host:scam-payment-risk-check user$ - S13 investment: allowed set must be ALLOW, not WARN/HOLD.
-bash: -: command not found
host:scam-payment-risk-check user$ Change only these labels, rerun make eval, and show the results. Do not change rules or thresholds.
host:scam-payment-risk-check user$ .venv/bin/python - <<'EOF'
> import json
> rows = [json.loads(l) for l in open("sample-data/scenarios.jsonl") if l.strip()]
> scam = next(s for s in rows if s.get("must_hold"))
> good = next(s for s in rows if s.get("is_scam") is False and isinstance(s.get("request"), dict) and "payee" in s["request"])
> bad = json.loads(json.dumps(good["request"])); bad["payee"]["bsb"] = "12AB"
> for name, req in (("scam", scam["request"]), ("genuine", good["request"]), ("invalid", bad)):
>     json.dump(req, open(f"/tmp/{name}.json", "w"), indent=1)
> r = scam["request"]
> print("Search the logs for these. They must NOT appear:")
> print("  account:", r["payee"]["account_number"], "| amount:", r["amount"], "| payee name:", r["payee"]["name"])
> EOF
Search the logs for these. They must NOT appear:
  account: 70025691 | amount: 4800.00 | payee name: Sam Mockwell
host:scam-payment-risk-check user$ SCAMCHECK_AUDIT_PATH=/tmp/audit.jsonl make run-api 2>&1 | tee /tmp/api.log
.venv/bin/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000
INFO:     Started server process [44369]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
{"ts": "2026-11-07T06:08:31.343+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "d254067c-7c8c-4667-a936-155c9be23ab0", "decision": "HOLD", "mode": "NORMAL", "latency_ms": 0.473}
INFO:     127.0.0.1:57173 - "POST /v1/assess HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:09:06.344+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "49b2ce4b-1c43-460b-8391-ae4e0a6500bb", "decision": "REJECT", "mode": "NORMAL", "latency_ms": 0.22}
INFO:     127.0.0.1:57176 - "POST /v1/assess HTTP/1.1" 422 Unprocessable Entity
INFO:     127.0.0.1:57178 - "GET /v1/audit?limit=5 HTTP/1.1" 200 OK
INFO:     127.0.0.1:57239 - "POST /v1/demo/model-failure HTTP/1.1" 403 Forbidden
^Chost:scam-payment-risk-check user$ 
host:scam-payment-risk-check user$ curl -s -X POST localhost:8000/v1/assess -H "Content-Type: application/json" -d @/tmp/scam.json
{"decision_id":"d254067c-7c8c-4667-a936-155c9be23ab0","request_id":"S01","decision":"HOLD","risk_score":0.9626,"reasons":[{"code":"R03_ON_CALL_NEW_PAYEE_HIGH_VALUE","detail":"High-value payment to a new payee during an active call (high value is 3000 AUD or more)."},{"code":"R05_UNUSUAL_AMOUNT","detail":"Amount is at least 5 times the customer's typical payment."},{"code":"M_AMOUNT_ABOVE_TYPICAL","detail":"Amount is high compared with typical payments."},{"code":"M_NEW_PAYEE","detail":"Payment to a payee the customer has not paid before."}],"mode":"NORMAL","model_version":"risk_model_v1","policy_version":"2026.11.1","latency_ms":0.473}host:scam-payment-risk-check user$ 
host:scam-payment-risk-check user$ curl -s -w "\nHTTP %{http_code}\n" -X POST localhost:8000/v1/assess -H "Content-Type: application/json" -d @/tmp/invalid.json
{"decision_id":"49b2ce4b-1c43-460b-8391-ae4e0a6500bb","request_id":"G01","decision":"REJECT","risk_score":null,"reasons":[{"code":"INVALID_BSB","detail":"payee.bsb: BSB must be exactly 6 digits."}],"mode":"NORMAL","model_version":null,"policy_version":"2026.11.1","latency_ms":0.22}
HTTP 422
host:scam-payment-risk-check user$ grep -n -e "ACCOUNT_NUMBER" -e "AMOUNT" -e "PAYEE_NAME" /tmp/api.log
host:scam-payment-risk-check user$ tail -5 /tmp/api.log
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
{"ts": "2026-11-07T06:08:31.343+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "d254067c-7c8c-4667-a936-155c9be23ab0", "decision": "HOLD", "mode": "NORMAL", "latency_ms": 0.473}
INFO:     127.0.0.1:57173 - "POST /v1/assess HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:09:06.344+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "49b2ce4b-1c43-460b-8391-ae4e0a6500bb", "decision": "REJECT", "mode": "NORMAL", "latency_ms": 0.22}
INFO:     127.0.0.1:57176 - "POST /v1/assess HTTP/1.1" 422 Unprocessable Entity
host:scam-payment-risk-check user$ curl -s "localhost:8000/v1/audit?limit=5"
{"count":2,"records":[{"amount":null,"customer_id":"cust-005","decision":"REJECT","decision_id":"49b2ce4b-1c43-460b-8391-ae4e0a6500bb","latency_ms":0.22,"mode":"NORMAL","model_version":null,"payee_account_masked":"*****936","policy_version":"2026.11.1","prev_hash":"7d62f8c1d66797954f51f41ae34d93be00ffbb84e8237ebb3e29a1190fca4e73","reasons":[{"code":"INVALID_BSB","detail":"payee.bsb: BSB must be exactly 6 digits."}],"record_hash":"404e78087041c8962c023460b0f4d57c8251287d3780f3fd11657fef2ffb1133","request_hash":"b3996019980d93d8d31c6b16e7842ca936449049bf5e46e94ad894ed45f6d343","risk_score":null,"ts":"2026-11-07T06:09:06.342+00:00"},{"amount":"4800.00","customer_id":"cust-002","decision":"HOLD","decision_id":"d254067c-7c8c-4667-a936-155c9be23ab0","latency_ms":0.473,"mode":"NORMAL","model_version":"risk_model_v1","payee_account_masked":"*****691","policy_version":"2026.11.1","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","reasons":[{"code":"R03_ON_CALL_NEW_PAYEE_HIGH_VALUE","detail":"High-value payment to a new payee during an active call (high value is 3000 AUD or more)."},{"code":"R05_UNUSUAL_AMOUNT","detail":"Amount is at least 5 times the customer's typical payment."},{"code":"M_AMOUNT_ABOVE_TYPICAL","detail":"Amount is high compared with typical payments."},{"code":"M_NEW_PAYEE","detail":"Payment to a payee the customer has not paid before."}],"record_hash":"7d62f8c1d66797954f51f41ae34d93be00ffbb84e8237ebb3e29a1190fca4e73","request_hash":"e90b3d0edcb7c407dc9c4a3f8c2ff963417e440d118c267bd072674ad3e50242","risk_score":0.9626,"ts":"2026-11-07T06:08:31.342+00:00"}]}host:scam-payment-risk-check user$ SCAMCHECK_AUDIT_PATH=/tmp/audit.jsonl .venv/bin/scamcheck verify-audit
{
  "ok": true,
  "records": 2,
  "message": "chain intact (2 records)",
  "first_bad_line": null
}
host:scam-payment-risk-check user$ cp /tmp/audit.jsonl /tmp/audit_tampered.jsonl && sed -i '' '1s/"HOLD"/"ALLOW"/' /tmp/audit_tampered.jsonl
host:scam-payment-risk-check user$ SCAMCHECK_AUDIT_PATH=/tmp/audit_tampered.jsonl .venv/bin/scamcheck verify-audit
{
  "ok": false,
  "records": 0,
  "message": "record_hash does not match the record contents (record edited)",
  "first_bad_line": 1
}
host:scam-payment-risk-check user$ grep -rn "AUDIT_UNAVAILABLE" src/ tests/
src/scamcheck/health.py:45:        reasons.append("AUDIT_UNAVAILABLE")
Binary file src/scamcheck/__pycache__/engine.cpython-312.pyc matches
Binary file src/scamcheck/__pycache__/health.cpython-312.pyc matches
src/scamcheck/engine.py:242:    payment is held (reason ``AUDIT_UNAVAILABLE``, followed by the original reasons): a decision
src/scamcheck/engine.py:251:            code="AUDIT_UNAVAILABLE",
Binary file tests/__pycache__/test_cli.cpython-312-pytest-9.2.0.pyc matches
Binary file tests/__pycache__/test_engine_audit.cpython-312-pytest-9.2.0.pyc matches
Binary file tests/__pycache__/test_api.cpython-312-pytest-9.2.0.pyc matches
tests/test_api.py:134:    assert "AUDIT_UNAVAILABLE" in body["reasons"]
tests/test_api.py:172:    assert body["reasons"][0]["code"] == "AUDIT_UNAVAILABLE"
tests/test_cli.py:105:    assert body["reasons"][0]["code"] == "AUDIT_UNAVAILABLE"
tests/test_engine_audit.py:61:    assert codes(response)[0] == "AUDIT_UNAVAILABLE"
tests/test_engine_audit.py:70:    assert codes(held) == ["AUDIT_UNAVAILABLE", *codes(plain)]
tests/test_engine_audit.py:82:    assert codes(response) == ["AUDIT_UNAVAILABLE", "AMOUNT_NOT_POSITIVE"]
tests/test_engine_audit.py:95:    assert codes(response)[0] == "AUDIT_UNAVAILABLE"
tests/test_engine_audit.py:105:    assert codes(response)[0] == "AUDIT_UNAVAILABLE"
host:scam-payment-risk-check user$ touch /tmp/readonly.jsonl && chmod 444 /tmp/readonly.jsonl
host:scam-payment-risk-check user$ SCAMCHECK_AUDIT_PATH=/tmp/readonly.jsonl .venv/bin/scamcheck assess --file /tmp/genuine.json
Audit write failed (AuditError); decision forced to HOLD
{
  "decision_id": "6b29f499-306f-420a-a2c1-f74f40d6aad6",
  "request_id": "G01",
  "decision": "HOLD",
  "risk_score": 0.0137,
  "reasons": [
    {
      "code": "AUDIT_UNAVAILABLE",
      "detail": "The audit trail could not be written; payment held."
    },
    {
      "code": "NO_RISK_SIGNALS",
      "detail": "No risk signals were triggered."
    }
  ],
  "mode": "NORMAL",
  "model_version": "risk_model_v1",
  "policy_version": "2026.11.1",
  "latency_ms": 6.725
}
host:scam-payment-risk-check user$ curl -s -w "\nHTTP %{http_code}\n" -X POST localhost:8000/v1/demo/model-failure -H "Content-Type: application/json" -d '{"enabled": true}'
{"detail":"Demo mode is off. Set SCAMCHECK_DEMO_MODE=1 to enable it."}
HTTP 403
host:scam-payment-risk-check user$ cat Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Unprivileged user; the app never runs as root.
RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only what the service needs at runtime (no tests, scripts, training data or evidence).
COPY src/ src/
COPY config/policy.toml config/policy.toml
COPY models/ models/
COPY sample-data/reference/ sample-data/reference/
COPY sample-data/scenarios.jsonl sample-data/scenarios_hard.jsonl sample-data/

# The audit trail is written here (mounted as a volume by docker-compose).
RUN mkdir -p /app/audit && chown app:app /app/audit

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import sys, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2); sys.exit(0 if r.status == 200 else 1)"

# One worker: the loaded model and the demo switch live in process memory.
CMD ["uvicorn", "scamcheck.api:app", "--host", "0.0.0.0", "--port", "8000"]
host:scam-payment-risk-check user$ cat .dockerignore
.git
.github
.venv
.pytest_cache
.ruff_cache
**/__pycache__
**/*.pyc
**/*.egg-info
audit
tests
scripts
evidence
sample-data/training
.env
.env.*
host:scam-payment-risk-check user$ docker compose up --build
[+] Building 1.1s (18/18) FINISHED                                                                                                                 
 => [internal] load local bake definitions                                                                                                    0.0s
 => => reading from stdin 562B                                                                                                                0.0s
 => [internal] load build definition from Dockerfile                                                                                          0.0s
 => => transferring dockerfile: 1.15kB                                                                                                        0.0s
 => [internal] load metadata for docker.io/library/python:3.12-slim                                                                           0.0s
 => [internal] load .dockerignore                                                                                                             0.0s
 => => transferring context: 187B                                                                                                             0.0s
 => [ 1/11] FROM docker.io/library/python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54                   0.0s
 => => resolve docker.io/library/python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54                     0.0s
 => [internal] load build context                                                                                                             0.0s
 => => transferring context: 1.21kB                                                                                                           0.0s
 => CACHED [ 2/11] RUN useradd --create-home --uid 10001 app                                                                                  0.0s
 => CACHED [ 3/11] WORKDIR /app                                                                                                               0.0s
 => CACHED [ 4/11] COPY requirements.txt .                                                                                                    0.0s
 => CACHED [ 5/11] RUN pip install --no-cache-dir -r requirements.txt                                                                         0.0s
 => CACHED [ 6/11] COPY src/ src/                                                                                                             0.0s
 => CACHED [ 7/11] COPY config/policy.toml config/policy.toml                                                                                 0.0s
 => CACHED [ 8/11] COPY models/ models/                                                                                                       0.0s
 => CACHED [ 9/11] COPY sample-data/reference/ sample-data/reference/                                                                         0.0s
 => CACHED [10/11] COPY sample-data/scenarios.jsonl sample-data/scenarios_hard.jsonl sample-data/                                             0.0s
 => CACHED [11/11] RUN mkdir -p /app/audit && chown app:app /app/audit                                                                        0.0s
 => exporting to image                                                                                                                        0.2s
 => => exporting layers                                                                                                                       0.0s
 => => exporting manifest sha256:68fd94ea3a77749030d4faae241044fa429bd36fd35e95f77ecd46ade3bd9b9b                                             0.0s
 => => exporting config sha256:9daef9f8d6696c7c8363d2958980e7389031171b9d724a8cb9ec1b4ae1924430                                               0.0s
 => => exporting attestation manifest sha256:0283baa04ebc40261be429f8cb21a5f34998044d8eadf896375d95cf1ae7934c                                 0.0s
 => => exporting manifest list sha256:e526d3f230edebba048962c59c8af872200e7dddf2d6253ba36fe4254eb0e5fb                                        0.0s
 => => naming to docker.io/library/scamcheck:local                                                                                            0.0s
 => => unpacking to docker.io/library/scamcheck:local                                                                                         0.0s
 => resolving provenance for metadata file                                                                                                    0.0s
[+] up 4/4
 ✔ Image scamcheck:local                         Built                                                                                         1.4s
 ✔ Volume scam-payment-risk-check_audit-data     Created                                                                                       0.0s
 ✔ Network scam-payment-risk-check_default       Created                                                                                       0.1s
 ✔ Container scam-payment-risk-check-scamcheck-1 Created                                                                                       0.1s
Attaching to scamcheck-1
scamcheck-1  | INFO:     Started server process [1]
scamcheck-1  | INFO:     Waiting for application startup.
scamcheck-1  | INFO:     Application startup complete.
scamcheck-1  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
scamcheck-1  | INFO:     127.0.0.1:44574 - "GET /health HTTP/1.1" 200 OK
scamcheck-1  | INFO:     127.0.0.1:51338 - "GET /health HTTP/1.1" 200 OK
Gracefully Stopping... press Ctrl+C again to force
Container scam-payment-risk-check-scamcheck-1 Stopping 
scamcheck-1  | INFO:     Shutting down
scamcheck-1  | INFO:     Waiting for application shutdown.
scamcheck-1  | INFO:     Application shutdown complete.
scamcheck-1  | INFO:     Finished server process [1]
Container scam-payment-risk-check-scamcheck-1 Stopped 
scamcheck-1 exited with code 0
host:scam-payment-risk-check user$ docker compose exec $(docker compose ps --services | head -1) id
requires at least 2 arg(s), only received 1
host:scam-payment-risk-check user$ docker compose up -d --build
[+] Building 2.9s (18/18) FINISHED                                                                                                                 
 => [internal] load local bake definitions                                                                                                    0.0s
 => => reading from stdin 562B                                                                                                                0.0s
 => [internal] load build definition from Dockerfile                                                                                          0.0s
 => => transferring dockerfile: 1.15kB                                                                                                        0.0s
 => [internal] load metadata for docker.io/library/python:3.12-slim                                                                           0.0s
 => [internal] load .dockerignore                                                                                                             0.0s
 => => transferring context: 187B                                                                                                             0.0s
 => [internal] load build context                                                                                                             0.0s
 => => transferring context: 10.53kB                                                                                                          0.0s
 => [ 1/11] FROM docker.io/library/python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54                   0.1s
 => => resolve docker.io/library/python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54                     0.1s
 => CACHED [ 2/11] RUN useradd --create-home --uid 10001 app                                                                                  0.0s
 => CACHED [ 3/11] WORKDIR /app                                                                                                               0.0s
 => CACHED [ 4/11] COPY requirements.txt .                                                                                                    0.0s
 => CACHED [ 5/11] RUN pip install --no-cache-dir -r requirements.txt                                                                         0.0s
 => [ 6/11] COPY src/ src/                                                                                                                    0.1s
 => [ 7/11] COPY config/policy.toml config/policy.toml                                                                                        0.1s
 => [ 8/11] COPY models/ models/                                                                                                              0.1s
 => [ 9/11] COPY sample-data/reference/ sample-data/reference/                                                                                0.1s
 => [10/11] COPY sample-data/scenarios.jsonl sample-data/scenarios_hard.jsonl sample-data/                                                    0.1s
 => [11/11] RUN mkdir -p /app/audit && chown app:app /app/audit                                                                               0.3s
 => exporting to image                                                                                                                        1.0s
 => => exporting layers                                                                                                                       0.6s
 => => exporting manifest sha256:fadf9908ac0fbb48d9d4524da14dbf869a567348759364be2ddc4c286a9803e5                                             0.0s
 => => exporting config sha256:aa770980959146f17fac8eaf168f0ee37511a9996df9fb7d7e9902a99f246fe3                                               0.0s
 => => exporting attestation manifest sha256:bffa087c49a57494b318ec2e3b20825d16d7db2ddfa4ea3e842d4afbe34a2a7d                                 0.1s
 => => exporting manifest list sha256:e0e9a8c6df1c0d71d71afc58efb6a5c4e76aadce91e374cc6c01b4f945a0b511                                        0.0s
 => => naming to docker.io/library/scamcheck:local                                                                                            0.0s
 => => unpacking to docker.io/library/scamcheck:local                                                                                         0.2s
 => resolving provenance for metadata file                                                                                                    0.0s
[+] up 2/2
 ✔ Image scamcheck:local                         Built                                                                                         3.1s
 ✔ Container scam-payment-risk-check-scamcheck-1 Started                                                                                       0.5s
host:scam-payment-risk-check user$ docker compose exec $(docker compose ps --services | head -1) id
uid=10001(app) gid=10001(app) groups=10001(app)
host:scam-payment-risk-check user$ requires at least 2 arg(s), only received 1
-bash: syntax error near unexpected token `('
host:scam-payment-risk-check user$ docker compose config --services
scamcheck
host:scam-payment-risk-check user$ docker compose exec api id
service "api" is not running
host:scam-payment-risk-check user$ docker compose exec scamcheck id
uid=10001(app) gid=10001(app) groups=10001(app)
host:scam-payment-risk-check user$ docker compose ps -a
NAME                                  IMAGE             COMMAND                  SERVICE     CREATED         STATUS                   PORTS
scam-payment-risk-check-scamcheck-1   scamcheck:local   "uvicorn scamcheck.a…"   scamcheck   2 minutes ago   Up 2 minutes (healthy)   127.0.0.1:8000->8000/tcp
host:scam-payment-risk-check user$ docker compose logs --tail 40
scamcheck-1  | INFO:     Started server process [1]
scamcheck-1  | INFO:     Waiting for application startup.
scamcheck-1  | INFO:     Application startup complete.
scamcheck-1  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
scamcheck-1  | INFO:     127.0.0.1:45730 - "GET /health HTTP/1.1" 200 OK
scamcheck-1  | INFO:     127.0.0.1:49344 - "GET /health HTTP/1.1" 200 OK
scamcheck-1  | INFO:     127.0.0.1:34916 - "GET /health HTTP/1.1" 200 OK
scamcheck-1  | INFO:     127.0.0.1:54688 - "GET /health HTTP/1.1" 200 OK
scamcheck-1  | INFO:     127.0.0.1:33390 - "GET /health HTTP/1.1" 200 OK
host:scam-payment-risk-check user$ docker compose down
[+] down 2/2
 ✔ Container scam-payment-risk-check-scamcheck-1 Removed                                                                                       0.8s
 ✔ Network scam-payment-risk-check_default       Removed                                                                                       0.1s
host:scam-payment-risk-check user$ gh run list --limit 3
no runs found
host:scam-payment-risk-check user$ gh run watch
found no in progress runs to watch
host:scam-payment-risk-check user$ gh run list --limit 3
STATUS  TITLE                                                WORKFLOW  BRANCH  EVENT  ID           ELAPSED  AGE                   
*       ci: docker image and GitHub Actions verify workflow  ci        main    push   42346647521  3s       less than a minute ago
host:scam-payment-risk-check user$ gh run watch
? Select a workflow run * ci: docker image and GitHub Actions verify workflow, ci [main] 9s ago
✓ main ci · 42346647521
Triggered via push less than a minute ago

JOBS
✓ verify in 18s (ID 128325737313)
  ✓ Set up job
  ✓ Run actions/checkout@v4
  ✓ Run actions/setup-python@v5
  ✓ Set up the environment
  ✓ Lint, format check, tests and evaluation gate
  ✓ Post Run actions/setup-python@v5
  ✓ Post Run actions/checkout@v4
  ✓ Complete job

ANNOTATIONS
! Node.js 20 is deprecated. The following actions target Node.js 20 but are being forced to run on Node.js 24: actions/checkout@v4, actions/setup-python@v5. For more information see: https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/
verify: .github#2

- "The ubuntu-latest label will migrate to Ubuntu 26 beginning October 19, 2026. For more information, see https://github.com/actions/runner-images/issues/14748"
verify: .github#1


✓ Run ci (42346647521) completed with 'success'
host:scam-payment-risk-check user$ 
host:scam-payment-risk-check user$ gh run view --log-failed
? Select a workflow run ✓ ci: docker image and GitHub Actions verify workflow, ci [main] 40s ago
host:scam-payment-risk-check user$ grep -n -i "concurren" evidence/operate.md
host:scam-payment-risk-check user$ docker compose down
host:scam-payment-risk-check user$ SCAMCHECK_DEMO_MODE=1 SCAMCHECK_AUDIT_PATH=/tmp/ui-audit.jsonl make run-api
.venv/bin/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000
INFO:     Started server process [45884]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
ERROR:    [Errno 48] error while attempting to bind on address ('127.0.0.1', 8000): [errno 48] address already in use
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
make: *** [run-api] Error 3
host:scam-payment-risk-check user$ SCAMCHECK_DEMO_MODE=1 SCAMCHECK_AUDIT_PATH=/tmp/ui-audit.jsonl make run-api
.venv/bin/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000
INFO:     Started server process [46144]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
ERROR:    [Errno 48] error while attempting to bind on address ('127.0.0.1', 8000): [errno 48] address already in use
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
make: *** [run-api] Error 3
host:scam-payment-risk-check user$ docker compose down
host:scam-payment-risk-check user$ SCAMCHECK_DEMO_MODE=1 SCAMCHECK_AUDIT_PATH=/tmp/ui-audit.jsonl make run-api
.venv/bin/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000
INFO:     Started server process [46228]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     127.0.0.1:57338 - "GET / HTTP/1.1" 200 OK
INFO:     127.0.0.1:57338 - "GET /static/styles.css HTTP/1.1" 200 OK
INFO:     127.0.0.1:57340 - "GET /static/app.js HTTP/1.1" 200 OK
INFO:     127.0.0.1:57340 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57338 - "GET /v1/scenarios HTTP/1.1" 200 OK
INFO:     127.0.0.1:57342 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
INFO:     127.0.0.1:57344 - "GET /favicon.ico HTTP/1.1" 204 No Content
{"ts": "2026-11-07T06:34:22.685+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "3fbb3021-95fe-4c8b-8f89-485ceb887e55", "decision": "HOLD", "mode": "NORMAL", "latency_ms": 3.777}
INFO:     127.0.0.1:57346 - "POST /v1/assess HTTP/1.1" 200 OK
INFO:     127.0.0.1:57346 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57348 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
INFO:     127.0.0.1:57348 - "POST /v1/eval HTTP/1.1" 200 OK
INFO:     127.0.0.1:57348 - "GET /health HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:35:40.841+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "5bad2765-d1aa-4b27-a912-499f2d0d08e2", "decision": "HOLD", "mode": "NORMAL", "latency_ms": 0.417}
INFO:     127.0.0.1:57350 - "POST /v1/assess HTTP/1.1" 200 OK
INFO:     127.0.0.1:57350 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57352 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:35:56.130+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "b5a74913-2c4e-438a-956d-5b54c4403e82", "decision": "HOLD", "mode": "NORMAL", "latency_ms": 0.314}
INFO:     127.0.0.1:57355 - "POST /v1/assess HTTP/1.1" 200 OK
INFO:     127.0.0.1:57355 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57357 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:36:28.048+00:00", "level": "WARNING", "logger": "scamcheck.api", "message": "Demo: simulated model failure on; running in DEGRADED_RULES_ONLY mode"}
INFO:     127.0.0.1:57359 - "POST /v1/demo/model-failure HTTP/1.1" 200 OK
INFO:     127.0.0.1:57359 - "GET /health HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:36:36.873+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "c2995df8-40d1-4159-9c24-ac09c91c8710", "decision": "ALLOW", "mode": "DEGRADED_RULES_ONLY", "latency_ms": 0.175}
INFO:     127.0.0.1:57361 - "POST /v1/assess HTTP/1.1" 200 OK
INFO:     127.0.0.1:57361 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57363 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:36:58.537+00:00", "level": "WARNING", "logger": "scamcheck.api", "message": "Demo: simulated model failure off"}
INFO:     127.0.0.1:57367 - "POST /v1/demo/model-failure HTTP/1.1" 200 OK
INFO:     127.0.0.1:57367 - "GET /health HTTP/1.1" 200 OK
^CINFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [46228]

host:scam-payment-risk-check user$ SCAMCHECK_AUDIT_PATH=/tmp/ui-audit.jsonl make run-api
.venv/bin/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000
INFO:     Started server process [46313]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     127.0.0.1:57370 - "GET / HTTP/1.1" 200 OK
INFO:     127.0.0.1:57372 - "GET /static/app.js HTTP/1.1" 200 OK
INFO:     127.0.0.1:57370 - "GET /static/styles.css HTTP/1.1" 200 OK
INFO:     127.0.0.1:57370 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57376 - "GET /favicon.ico HTTP/1.1" 204 No Content
INFO:     127.0.0.1:57372 - "GET /v1/scenarios HTTP/1.1" 200 OK
INFO:     127.0.0.1:57374 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
{"ts": "2026-11-07T06:37:59.929+00:00", "level": "INFO", "logger": "scamcheck.api", "message": "decision", "decision_id": "a7951567-68c5-4a66-b54a-d9cd5321b373", "decision": "HOLD", "mode": "NORMAL", "latency_ms": 0.398}
INFO:     127.0.0.1:57378 - "POST /v1/assess HTTP/1.1" 200 OK
INFO:     127.0.0.1:57378 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57380 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
INFO:     127.0.0.1:57382 - "POST /v1/audit/verify HTTP/1.1" 200 OK
INFO:     127.0.0.1:57382 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57384 - "POST /v1/eval HTTP/1.1" 200 OK
INFO:     127.0.0.1:57384 - "GET /health HTTP/1.1" 200 OK
^CINFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [46313]

host:scam-payment-risk-check user$ make verify 2>&1 | tee /tmp/verify.txt
.venv/bin/ruff check .
All checks passed!
.venv/bin/ruff format --check .
48 files already formatted
.venv/bin/pytest
============================= test session starts ==============================
platform darwin -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0
rootdir: /Users/user/MyApps/scam-payment-risk-check
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.16.0
collected 516 items

tests/test_api.py ...................................                    [  6%]
tests/test_audit.py .................................................... [ 16%]
.                                                                        [ 17%]
tests/test_cli.py ................                                       [ 20%]
tests/test_deployment_files.py ......                                    [ 21%]
tests/test_engine.py .........................................           [ 29%]
tests/test_engine_audit.py .................                             [ 32%]
tests/test_engine_model.py ............................................. [ 41%]
......                                                                   [ 42%]
tests/test_evaluate.py ......................................            [ 49%]
tests/test_generate_reference_data.py ...                                [ 50%]
tests/test_model.py ................................................     [ 59%]
tests/test_policy.py ..................                                  [ 63%]
tests/test_reference.py ...................                              [ 66%]
tests/test_rules.py .......................................              [ 74%]
tests/test_schemas.py .................................................. [ 84%]
                                                                         [ 84%]
tests/test_signals.py ..............................                     [ 89%]
tests/test_training_scripts.py ................                          [ 93%]
tests/test_ui.py ...................................                     [ 99%]
tests/test_version.py .                                                  [100%]

=============================== warnings summary ===============================
.venv/lib/python3.12/site-packages/fastapi/testclient.py:1
  /Users/user/MyApps/scam-payment-risk-check/.venv/lib/python3.12/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================= 516 passed, 1 warning in 11.45s ========================
.venv/bin/python -m scamcheck.evaluate
PASS  1. All must-hold scenarios are HOLD: 14/14 must-hold scenarios held
PASS  2. Scams caught (WARN or HOLD): 19/19 scams warned or held (100.0%); need >= 90%
PASS  3. Genuine payments held within budget: 1/12 genuine scenarios held (8.3%); allow <= 10%. Held: G04 -> HOLD [R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE]
PASS  4. Every non-REJECT decision has a reason: 34/34 non-REJECT decisions have a reason
PASS  5. Two runs give identical decisions: 39/39 scenarios identical across two runs
PASS  6. Must-hold scenarios still HOLD with a tampered model: tamper detected (MODEL_INTEGRITY_FAILED); 14/14 must-hold scenarios held in DEGRADED_RULES_ONLY; degrade warnings logged: 1
MISMATCH  G04: expected ALLOW/WARN, got HOLD ['R05_UNUSUAL_AMOUNT', 'M_AMOUNT_ABOVE_TYPICAL', 'M_NEW_PAYEE']
known limitations (non-gating): 0/6 match the correct answer
report: /Users/user/MyApps/scam-payment-risk-check/evidence/eval-report.md
host:scam-payment-risk-check user$ grep -E "passed|failed|GATE|gate" /tmp/verify.txt
All checks passed!
======================= 516 passed, 1 warning in 11.45s ========================
host:scam-payment-risk-check user$ grep -i -E "gate|recall|hold|pass|fail|total" evidence/eval-report.md | head -20
- Overall: **PASS**
## Gate results
| Gate | Result | Detail |
| 1. All must-hold scenarios are HOLD | PASS | 14/14 must-hold scenarios held |
| 2. Scams caught (WARN or HOLD) | PASS | 19/19 scams warned or held (100.0%); need >= 90% |
| 3. Genuine payments held within budget | PASS | 1/12 genuine scenarios held (8.3%); allow <= 10%. Held: G04 -> HOLD [R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE] |
| 4. Every non-REJECT decision has a reason | PASS | 34/34 non-REJECT decisions have a reason |
| 5. Two runs give identical decisions | PASS | 39/39 scenarios identical across two runs |
| 6. Must-hold scenarios still HOLD with a tampered model | PASS | tamper detected (MODEL_INTEGRITY_FAILED); 14/14 must-hold scenarios held in DEGRADED_RULES_ONLY; degrade warnings logged: 1 |
| Must-hold scenarios held | 14/14 |
| Scenarios passing (decision and expected reason codes) | 38/39 |
| S01 | impersonation | yes | HOLD (must hold) | HOLD | 0.9626 | R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S02 | impersonation | yes | WARN/HOLD | HOLD | 0.9634 | R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S03 | impersonation | yes | HOLD (must hold) | HOLD | 0.9376 | R02_REMOTE_ACCESS_NEW_PAYEE, M_NEW_PAYEE, M_REMOTE_ACCESS | PASS |
| S04 | impersonation | yes | HOLD (must hold) | HOLD | 0.9821 | R03_ON_CALL_NEW_PAYEE_HIGH_VALUE, R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE | PASS |
| S05 | remote_access | yes | HOLD (must hold) | HOLD | 0.8241 | R02_REMOTE_ACCESS_NEW_PAYEE, M_NEW_PAYEE, M_REMOTE_ACCESS | PASS |
| S06 | remote_access | yes | HOLD (must hold) | HOLD | 0.9768 | R02_REMOTE_ACCESS_NEW_PAYEE, R05_UNUSUAL_AMOUNT, M_NEW_PAYEE, M_REMOTE_ACCESS | PASS |
| S07 | mule_payee | yes | HOLD (must hold) | HOLD | 0.7911 | R01_MULE_PAYEE, R06_YOUNG_PAYEE_ACCOUNT, M_NEW_PAYEE, M_YOUNG_PAYEE_ACCOUNT | PASS |
| S08 | mule_payee | yes | HOLD (must hold) | HOLD | 0.9141 | R01_MULE_PAYEE, R04_PAYEE_NAME_MISMATCH, R06_YOUNG_PAYEE_ACCOUNT, M_NEW_PAYEE, M_NAME_MISMATCH | PASS |
| S09 | mule_payee | yes | HOLD (must hold) | HOLD | 0.0793 | R01_MULE_PAYEE | PASS |
host:scam-payment-risk-check user$ grep -n -E "[0-9]+ (tests|passed|scenarios|checks|gates)|[0-9]+(\.[0-9]+)?%" README.md evidence/*.md
README.md:125:At the time of writing: 516 tests pass and all six gates pass. Details in
README.md:138:  the friction gate (at most 10% of genuine held) has little headroom (1 of 12).
evidence/decisions.md:32:- **Evaluation discipline.** Scenario labels were written before the first run and were not changed to make a gate pass; the gate limits (90% scams caught, 10% genuine held) are not tuned. Cases the system gets wrong live in a separate non-gating file and are reported on every run. One rule (R07, a young payee account with a high-value amount gives HOLD) was added test-first (scenario S19 failed before it and passes after) and its cost is accepted and visible: genuine high-value payments to accounts under 30 days old are held (case X06).
evidence/eval-report.md:15:| 2. Scams caught (WARN or HOLD) | PASS | 19/19 scams warned or held (100.0%); need >= 90% |
evidence/eval-report.md:16:| 3. Genuine payments held within budget | PASS | 1/12 genuine scenarios held (8.3%); allow <= 10%. Held: G04 -> HOLD [R05_UNUSUAL_AMOUNT, M_AMOUNT_ABOVE_TYPICAL, M_NEW_PAYEE] |
evidence/eval-report.md:18:| 5. Two runs give identical decisions | PASS | 39/39 scenarios identical across two runs |
evidence/intent.md:46:1. 100% of "must-hold" scam scenarios are held.
evidence/intent.md:47:2. At least 90% of scam scenarios result in WARN or HOLD.
evidence/intent.md:48:3. At most 10% of genuine scenarios are held (customer friction budget).
evidence/verify.md:13:| `pytest` | **516 passed**, 1 warning (Starlette's test client suggests an `httpx2` package; not adopted, no new dependencies) |
evidence/verify.md:22:| 2. Scams warned or held (need at least 90%) | 19/19 |
evidence/verify.md:23:| 3. Genuine payments held (allow at most 10%) | 1/12 (8.3%): G04, a genuine car purchase from a new payee, scored 0.7284 against the 0.70 hold line |
evidence/verify.md:44:- **Local:** `make verify` (above). Not part of it, but done by hand: the API driven with curl (scam, genuine, audit verify, live tamper of the audit file); `docker compose up --build` (image builds, container healthy and non-root, same results, audit chain survives a restart, UI served with its headers); the web UI driven in headless Chrome by a scratch script (25 of 25 checks, including HTML injection attempts rendering as text and no CSP violations); a clean-clone check of the README (see the end of this file).
host:scam-payment-risk-check user$ grep -n -i -E "zero hallucination|bulletproof|production-ready|guarantee|fully secure|100% (safe|accurate)|seamless|robust|enterprise-grade" README.md evidence/*.md
evidence/operate.md:42:Verify regularly. **Concurrency:** appends are serialised by a thread lock plus a POSIX `flock`, so several threads, or several processes on the same host and a local filesystem, can share one audit file (tested with 200 threaded appends and 4 processes x 25 appends). It is not safe across hosts or on network or shared filesystems. The single-file log is for the demo and local use only: production needs a proper store (WORM or object-lock storage, or a database with append-only guarantees) and the latest `record_hash` kept off the box. Removal of the newest records is not detectable from the file alone.
host:scam-payment-risk-check user$ awk '/^```/{f=!f; next} f' README.md
docker compose up --build
make setup      # creates .venv, installs pinned dependencies, installs the package and the CLI
make verify     # ruff, format check, tests and the evaluation gate (see below)
make run-api    # web UI and API on http://127.0.0.1:8000 (one worker)
.venv/bin/scamcheck assess --file /tmp/request.json   # one decision as JSON; exit 1 if REJECT
.venv/bin/scamcheck eval                              # evaluation gate; writes evidence/eval-report.md
.venv/bin/scamcheck verify-audit                      # recompute the audit hash chain
.venv/bin/scamcheck health                            # model, policy, reference data, audit
{
  "request_id": "demo-001",
  "timestamp": "2026-11-07T10:30:00+11:00",
  "customer_id": "cust-002",
  "amount": "4800.00",
  "currency": "AUD",
  "payee": { "name": "Sam Mockwell", "bsb": "000102", "account_number": "70025691" },
  "channel": "mobile",
  "session": { "on_active_call": true, "remote_access_detected": false, "new_device": true }
}
.venv/bin/scamcheck assess --file /tmp/request.json
# or, with the service running:
curl -s -X POST localhost:8000/v1/assess -H 'content-type: application/json' -d @/tmp/request.json
{
  "decision_id": "cefc984e-127f-49d4-b84f-857977d616ed",
  "request_id": "demo-001",
  "decision": "HOLD",
  "risk_score": 0.9626,
  "reasons": [
    { "code": "R03_ON_CALL_NEW_PAYEE_HIGH_VALUE", "detail": "High-value payment to a new payee during an active call (high value is 3000 AUD or more)." },
    { "code": "R05_UNUSUAL_AMOUNT", "detail": "Amount is at least 5 times the customer's typical payment." },
    { "code": "M_AMOUNT_ABOVE_TYPICAL", "detail": "Amount is high compared with typical payments." },
    { "code": "M_NEW_PAYEE", "detail": "Payment to a payee the customer has not paid before." }
  ],
  "mode": "NORMAL",
  "model_version": "risk_model_v1",
  "policy_version": "2026.11.1",
  "latency_ms": 3.074
}
host:scam-payment-risk-check user$ SCAMCHECK_DEMO_MODE=1 SCAMCHECK_AUDIT_PATH=/tmp/ui-audit.jsonl make run-api
.venv/bin/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000
INFO:     Started server process [47221]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     127.0.0.1:57490 - "GET / HTTP/1.1" 200 OK
INFO:     127.0.0.1:57490 - "GET /static/styles.css HTTP/1.1" 304 Not Modified
INFO:     127.0.0.1:57492 - "GET /static/app.js HTTP/1.1" 304 Not Modified
INFO:     127.0.0.1:57492 - "GET /health HTTP/1.1" 200 OK
INFO:     127.0.0.1:57490 - "GET /v1/scenarios HTTP/1.1" 200 OK
INFO:     127.0.0.1:57496 - "GET /favicon.ico HTTP/1.1" 204 No Content
INFO:     127.0.0.1:57494 - "GET /v1/audit?limit=20 HTTP/1.1" 200 OK
^CINFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [47221]

host:scam-payment-risk-check user$ vi evidence/build-log.md
host:scam-payment-risk-check user$ 



---

# Review checklists, marked afterwards

Added after the build (7 Nov 2026). The terminal log above is unchanged; `L123` means line 123 of it.
Chat times are local.

How I marked them:
- `[x]` = I did this check. The evidence is a terminal-log line (`L...`) or a chat message.
- `[ ]` = not done by me as far as this log shows, or it failed. **"Claude re-check"** is the result of a
  check Claude ran after the build, so the item is known to hold. Tick it if you did it by hand and did not log it.

## [P1] Scaffold
- [ ] Versions pinned exactly (`==`), nothing beyond the allowed dependencies. Not in my log. Claude re-check: runtime `fastapi==0.162.0`, `uvicorn==0.54.0`, `pydantic==2.14.3`; dev `pytest==9.2.0`, `httpx==0.28.1`, `ruff==0.17.4`. The one extra is the build backend `setuptools==80.9.0` (flagged in the P1 summary; not a runtime dependency).
- [x] `make verify` really runs ruff and pytest. L10 `less Makefile`. The target runs `ruff check`, `ruff format --check`, `pytest`, then `make eval`.
- [ ] No `.venv` or cache in `git status`. Not in my log. Claude re-check: they are in `.gitignore`; 0 tracked venv or cache files.
- Likely issues: `python3.12` not found did not happen. Ruff `S101` on test asserts was handled as the checklist suggests: `"tests/**" = ["S101"]` in `pyproject.toml`, tests folder only.

## [P2] Schema and validation
- [x] Amount uses `Decimal`, not float. L11 `grep amount|float|Decimal schemas.py`: `amount: Annotated[Decimal, ...]`; floats only for `risk_score` and `latency_ms`.
- [x] Each invalid test checks the specific error code. L19 `grep assert|parametrize|raises tests/test_schemas.py` (`assert codes(...) == {expected}`); L50 `pytest`: 50 passed.
- [x] A naive timestamp is rejected. L53 snippet: `NAIVE_TIMESTAMP`; 3 decimals gives `AMOUNT_TOO_PRECISE`.
- [ ] `extra="forbid"` on the nested models too. Not in my log. Claude re-check: base class `_Strict` (`extra="forbid"`) is used by `Payee`, `Session`, `PaymentRequest`, `Reason`, `DecisionResponse`; tests send `payee.nickname` and `session.extra_flag` and get `UNKNOWN_FIELD`.
- Likely issue (fragile string matching) did not occur: `_code_for` maps by `error["type"]` and the last element of `error["loc"]`.

## [P3] Reference data and signals (SME review)
- [x] Customers look realistic. L78 table: tenure 20 to 5,100 days, typical amount 60 to 2,000, 0 to 5 known payees.
- [ ] Name matching is sensible. **FAILED, open.** L146 tried 8 name pairs (L124 first used a wrong function name). Two differ from what I expect: `J Smith` vs `John Smith` gives MATCH, `Smith, John` vs `John Smith` gives MISMATCH; I expected CLOSE for both. Not changed in this build; the tests still expect MATCH and MISMATCH. Re-checked after the build: same result.
- [x] Guard against a typical amount of 0. L173, L178, L195 grepped `amount_ratio|typical` in `signals.py` and the tests: `signals.py` divides with no guard. Claude re-check: the guard is at load time. The reference loader rejects `typical_payment_amount <= 0` (`gt=0`, `ReferenceFileMalformedError`), so 0 never reaches `signals.py`. There is no dedicated test for the zero case.
- [x] No real-looking BSBs. L78 snippet: every BSB is `000xxx`; all three files are labelled SYNTHETIC.
- Corrections to write down: the name-matching finding above. L209 `ls scripts/` showed the generator was missing, so I required it (L211, L215).

## [P4] Rules and engine (SME review)
- [x] Thresholds match my fraud judgement; changed and logged. L220 to L221 (`less`, `vi config/policy.toml`): `high_value_amount` 5000 to 3000, with the comment "impersonation amount usually is less than 5k". Also logged in `evidence/agentic-workflow.md`.
- [x] `>=` or `>` at each threshold; tests cover the boundary. L227 `grep >=|<=` in `rules.py`: `>=` for high value and ratio, `<` for account age. L233 grepped the tests for boundary literals. Boundary tests: R03 at the threshold, R05 at 4.9999 and 5, R06 at 29 and 30 days.
- [ ] Reason `detail` messages avoid account numbers and names. Not in my log. Claude re-check: rule details quote only policy thresholds; test `test_reason_text_has_no_amounts_or_identifiers`. Later, my API-log search (P7) found none.
- [x] Config loaded with `tomllib`, clear error when the file is missing. L2494 grep: `policy.py` uses `tomllib`. L2504 missing-file check: my command imported from the wrong module (`ImportError`). Claude re-ran it correctly and found a string path crashed with `AttributeError`; fixed. Re-checked after the build: `PolicyError: ...: file is missing or cannot be read`.
- Likely issue found: hard-coded values. L222 found `_MAX_ID_LENGTH = 64` in `engine.py`; L225 found the `TODO` in `signals.py`; L233 found test literals tied to 5000. This led to my follow-up "why are there hard coded values in engine.py?". L256 `pytest` showed 58 failures while the agent was mid-change, then L2388 showed 179 passed. **Still open:** the name-match "close" threshold (0.80) remains a default in `signals.py` with that TODO, not in `policy.toml`.

## [P5] Risk model and degrade mode
- [x] Training data is separate from the evaluation scenarios. L2516 and L2531 grepped `scenario|seed|split`: the generator says it is separate, seed 42, seeded held-out split. Claude re-check: `training_data.csv` is in `sample-data/training/`; the evaluator never reads it.
- [x] Coefficient signs make sense. L2551: all seven positive, including `on_active_call` +1.808 and `remote_access_detected` +2.096; intercept -4.277.
- [x] Metrics are not too good. L2551: PR-AUC 0.9127, recall 0.7533 at 0.5. The README and `verify.md` say these measure fit to invented patterns.
- [x] Degrade mode really fails safe; I read the code path. L2626 `grep degrad|fail_safe|rules_only|health` in `engine.py` and `model.py`. L2648 to L2680 my degrade script, then `echo " " >> models/risk_model_v1.json`: `MODEL_INTEGRITY_FAILED`, `DEGRADED_RULES_ONLY`, score `None`, the payment still HOLD. L2684 `git checkout` failed (the file was not tracked yet), so Claude restored it byte for byte.
- [x] Likely issue, sigmoid overflow. L2619 (wrong name) and L2624: `sigmoid(1000), sigmoid(-1000), sigmoid(0)` = `1.0 0.0 0.5`.
- [x] Likely issue, circular hash. L2594 to L2598: the hash is in a separate `.sha256` file; L2596 `shasum -a 256` of the JSON.

## [P6] Evaluation gate (the most important SME review)
- [x] Read every scenario label. L2686 to L2707 and L2882 my `scenarios_review.py` printed expected against actual with reasons (37 of 38; it crashed on V05, whose request is a plain string). Only G04 differs. Label change asked (L2966, chat 16:59) and then reverted (chat 17:01), so no label was changed.
- [x] Awkward genuine cases exist. Seen in the review: G03 house deposit 20,000 (WARN), G04 car purchase 4,000 (HOLD), G12 electrician 3,000; plus X04 to X06 in the hard file.
- [x] Did the agent "fix" a gate by editing labels or thresholds? No. All six gates passed on the first run. When the 5 hard cases made gates 2 and 3 fail, the agent stopped and reported. I asked "List every change you made to scenario labels, thresholds or rules after the first evaluation run" (chat 16:46): none. I chose to move the cases to a non-gating file (chat 16:53).
- [x] Likely issue, scenarios written to match the rules. I asked for "5 realistic scenarios that you expect the current system to get wrong" (chat 16:48). All 5 were wrong, as predicted.

## [P7] API, CLI, audit log, Docker, CI
- [x] Logs contain no amounts or account numbers. L2971 printed the values to search for (account 70025691, amount 4800.00, payee Sam Mockwell). My grep at L3003 searched the words `ACCOUNT_NUMBER`, `AMOUNT`, `PAYEE_NAME` (no matches), not those values. Claude re-check on my own `/tmp` files: `/tmp/api.log` has none of the values. `/tmp/audit.jsonl` has `4800.00` once, because it was written by the earlier audit format that still stored the amount; I then asked for it to be removed (chat 17:12), and the current code does not write it.
- [x] Audit failure path tested with a read-only path. L3043 `chmod 444`, L3044 `scamcheck assess`: HOLD with `AUDIT_UNAVAILABLE`, even for a genuine payment that scored 0.0137.
- [x] Container runs as non-root; no secrets or `.env` copied in. L3069 `cat Dockerfile`, L3101 `cat .dockerignore`, L3206 and L3214 `docker compose exec scamcheck id`: `uid=10001(app)`. Claude re-check of the image: no `.env`, key or secret files; the only environment variable with "key" in its name is `GPG_KEY`, set by the official python base image (the public key id for verifying Python downloads).
- [x] Demo endpoint returns 403 without `SCAMCHECK_DEMO_MODE=1`. L3066: 403 with the "Demo mode is off" message.
- [x] `docker compose up --build` starts and `/health` answers. L3117 to L3171: server started, `GET /health 200` from the container healthcheck, `Up ... (healthy)` at L3216. (No explicit `curl` of `/health` in this log.)
- [x] CI is green. L3233 to L3240 `gh run watch`: success in 18 s. L3266 `gh run view --log-failed`: nothing failed.
- Likely issues: FastAPI's own 422 format did not occur (the raw body goes through `validate_request`; invalid JSON gives a REJECT `INVALID_REQUEST`). Concurrency note: L3268 `grep concurren operate.md` found nothing; the note was added (chat 17:23).

## [P7b] Web UI (demo rehearsal)
- [ ] Run each demo step myself (scam HOLD, rent ALLOW, broken JSON REJECT). Partly in my log. The server log at L3289 to L3330 (demo mode on) shows a scam HOLD, the evaluation run, the degrade toggle on and off, and one ALLOW, but that ALLOW came while degrade was on. I do not see a rent ALLOW in normal mode or a broken-JSON REJECT (no 422) there. Claude re-check in a real browser: scam HOLD, G01 ALLOW, V01 and malformed JSON REJECT with error codes, all pass.
- [ ] XSS: payee name `<img src=x onerror=alert(1)>` shows as plain text. Not in my log. Claude ran this exact payload in headless Chrome, for a scam and a genuine scenario: no `<img>` on the page, no dialog, `alert()` never called, no console errors. The server never returns or stores the payee name, so it is not shown anywhere. HTML in an unknown field name and in `customer_id` (both are displayed) also rendered as text.
- [ ] Degrade mode: banner DEGRADED, and a risky high-value payment still HOLDs. Partly in my log: the server log shows the toggle on and off (L3316 and the line after the toggle is switched off); the one decision during degrade was ALLOW and I cannot tell from the log which scenario it was. Claude re-check: banner turns amber "DEGRADED (rules only, no risk model)"; S01 is still HOLD with score n/a in `DEGRADED_RULES_ONLY`.
- [x] Restart without demo mode: the toggle does not appear and the endpoint refuses. L3331 restarted without `SCAMCHECK_DEMO_MODE`. The refusal was checked with curl in P7 (L3066: 403). Claude re-check: no toggle rendered with demo mode off.
- [ ] Decisions are readable as text, not only by colour. Not in my log. Claude re-check: the card title says "Decision: HOLD" and the tables show the word; test `test_decisions_are_shown_as_text_not_only_colour`; screenshots reviewed.
- Likely issues: a 422 breaking the page did not occur (the REJECT card renders). Stale `app.js`: L3495 and L3496 show `304 Not Modified` for the static files (the browser revalidated them). **No "Running..." state:** `app.js` only disables the button and sets `aria-busy`; it shows no "Running..." text (the evaluation takes about half a second locally).

## [P8] Evidence pack
- [x] Every number in the docs matches real output. L3357 `make verify | tee` (516 passed, six gates pass), L3410 and L3413 grepped the verify output and `eval-report.md`, L3434 grepped counts and percentages in the README and notes.
- [x] No "zero hallucinations", "bulletproof" or "production-ready". L3448 grep: one hit, "append-only guarantees" in `operate.md:42`, which describes what a production store would need; left as is.
- [ ] The README example works when pasted, and the UI demo steps match the real UI. Partly in my log: L3450 extracted the README code blocks; L3488 ran the UI. I do not see the example pasted into `/tmp/request.json` and run. Claude re-check: followed the README in a clean clone (Docker and local); the example output matched and UI demo steps 1 to 6 passed (see `evidence/verify.md`).
- [ ] `evidence/agentic-workflow.md` written by me. In progress: a draft with `[YOU: ...]` markers.

## Summary
40 checkbox lines: your 36 checklist items, 3 of the "likely issues" that I also checked, and the `agentic-workflow.md` write-up. 29 are ticked from evidence in this log or in the chat. 11 are unticked: 1 failed (name matching), 1 is still in progress (the `agentic-workflow.md` write-up), and 9 have no trace, or only part of a trace, in this log; Claude's re-check of those 9 passed.

Open items these checks found:
1. Name matching: initials give MATCH and surname-first gives MISMATCH; I expect CLOSE. Not changed.
2. The name-match "close" threshold (0.80) is still a default in `signals.py` (TODO), not in `policy.toml`. The evidence notes were corrected to say so.
3. No dedicated test for a typical amount of 0 (the guard is at load time).
4. No visible "Running..." state in the UI.
5. Only the three direct dependencies are pinned; transitive ones are not (found in the clean-clone check).


---

## Update after the checklists: name matching and threshold fixed

The checklist items above are left as they were when I marked them. Two of the open items were fixed afterwards, on my instruction.

**[P3] Name matching (was FAILED, open): fixed.** Initials and reordered words are now CLOSE. MATCH needs the same words after normalising case, punctuation and spacing. Typos are still CLOSE by similarity. My 8 pairs from L146, before and after:

| Pair | Before | After |
|---|---|---|
| `John Smith` vs `John Smith` | MATCH | MATCH |
| `john  smith.` vs `JOHN SMITH` | MATCH | MATCH |
| `J Smith` vs `John Smith` | MATCH | **CLOSE** (my expectation) |
| `Smith, John` vs `John Smith` | MISMATCH | **CLOSE** (my expectation) |
| `Jon Smith` vs `John Smith` | CLOSE | CLOSE |
| `ACME Pty Ltd` vs `Acme Pty. Ltd.` | MATCH | MATCH |
| `Jane Doe` vs `John Smith` | MISMATCH | MISMATCH |
| `John Smith` vs `Smith Holdings` | MISMATCH | MISMATCH |

Ten more pairs I added (`J. Smith`, `J S`, `Smith, J`, `Smith, John Paul` vs `John Paul Smith`, `Smith Jones` vs `Jones Smith`, `K Smith` and others): the initials and reordered ones became CLOSE; `K Smith` and the rest are unchanged.

**[P4] The `0.80` close threshold (TODO at L225): fixed.** It is now `name_close_threshold` in `config/policy.toml`, validated and required, and the engine passes it to the signals. No copy of the value is left in code. The evidence notes were corrected to say all thresholds live in `policy.toml` again.

Result: 516 to 534 tests, `make verify` clean, `evidence/eval-report.md` byte-identical (no scenario result changed; the scenarios have no surname-first name). `policy_version` was not bumped. Tests that encoded the old behaviour were changed because I changed the requirement.

Open items that remain: 3 (no dedicated test for a typical amount of 0), 4 (no visible "Running..." state), 5 (transitive dependencies not pinned).

---

*Note: the hostname, username and home-directory paths in this log were redacted after the fact (`host`, `user`, `/Users/user`). Nothing else was changed: line numbers and all times are as originally recorded.*

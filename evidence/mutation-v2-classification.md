# Mutation Gate v2 — Classification of the existing survivors

- Tree: `e3198501c8508b84a5d544d85623eedff4239926` (fixed candidate, current HEAD)
- Population: v2 mutmut run — 2584 mutants over `src/mgk` on a disposable copy with the candidate suite plus 8 strengthened `test_mutation_v2_*` regression files.
- Every mutant has at least one covering test (0 no-tests). All 2584 mutations applied and ran; no parse-fail/invalid mutations.

## Exact counts by category

| Category | Count | Definition (MGK-MUTATION-GATE-V2) |
|---|---|---|
| KILLED | 2282 | mutation changes behavior; a covering test fails |
| SURVIVED_KILLABLE | 227 | mutation changes observable behavior; no current test catches it |
| EQUIVALENT_PROVEN | 75 | provably no behavioral difference (runtime-probe evidence recorded) |
| INVALID_MUTANT | 0 | none: all 2584 mutations applied and ran (meta exit codes 0/1/33/-24 only) |
| UNREACHABLE_PROVEN | 0 | none identified |
| INDETERMINATE | 0 | none: every mutant evaluated |

**MUTATION_SCORE_V2 = KILLED / (KILLED + SURVIVED_KILLABLE) = 2282 / 2509 = 90.953%** (threshold 90.0%)

## By module

| Module | KILLED | SURVIVED_KILLABLE | EQUIVALENT_PROVEN |
|---|---|---|---|
| arrow | 35 | 0 | 0 |
| authority | 177 | 7 | 0 |
| canonical | 148 | 26 | 4 |
| cha | 73 | 11 | 0 |
| cli | 210 | 63 | 9 |
| clock | 1 | 0 | 0 |
| crypto | 101 | 1 | 5 |
| executor | 207 | 13 | 0 |
| ledger | 384 | 23 | 11 |
| models | 5 | 0 | 0 |
| resource | 280 | 53 | 14 |
| saxp | 62 | 7 | 0 |
| state | 281 | 21 | 32 |
| verifier | 318 | 2 | 0 |

## EQUIVALENT_PROVEN evidence

### CODEC_CASE_ONLY (6)

str.encode/str.decode codec name differs only by case (Python codec names are case-insensitive); runtime probe confirms identical bytes.

- `mgk.canonical.x_canonicalize__mutmut_25`
- `mgk.canonical.x_parse_canonical__mutmut_16`
- `mgk.crypto.x_b64u_encode__mutmut_9`
- `mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_18`
- `mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_24`
- `mgk.state.xǁSecurityStateǁintegrity_check__mutmut_32`

### ENCODE_HANDLER (1)

str.encode/decode errors handler changed or removed; handler only consulted on error and validated inputs never fail encoding/decoding; removing 'strict' falls back to the documented Python default; runtime probe confirms identical bytes.

- `mgk.canonical.x_canonicalize__mutmut_27`

### FS_PATH_CASE_ONLY (9)

path-component case change only; the evaluation filesystem is case-insensitive (macOS APFS/HFS+), so the path resolves to the same file; runtime probe confirms.

- `mgk.cli.x_h14_smoke__mutmut_108`
- `mgk.cli.x_h14_smoke__mutmut_111`
- `mgk.cli.x_h14_smoke__mutmut_14`
- `mgk.cli.x_h14_smoke__mutmut_16`
- `mgk.cli.x_h14_smoke__mutmut_34`
- `mgk.cli.x_h14_smoke__mutmut_4`
- `mgk.cli.x_h14_smoke__mutmut_8`
- `mgk.cli.x_h14_smoke__mutmut_93`
- `mgk.cli.x_h14_smoke__mutmut_96`

### GETATTR_DEFAULT_ONLY (15)

getattr(os, 'O_NOFOLLOW'/'O_DIRECTORY', <default>) default changed; the attribute exists on the evaluation platform (O_NOFOLLOW=256, O_DIRECTORY=1048576, runtime probe), so the changed default is never used.

- `mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_60`
- `mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_63`
- `mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_66`
- `mgk.resource.xǁResourceGuardǁ_open_file__mutmut_10`
- `mgk.resource.xǁResourceGuardǁ_open_file__mutmut_13`
- `mgk.resource.xǁResourceGuardǁ_open_file__mutmut_7`
- `mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_11`
- `mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_14`
- `mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_8`
- `mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_54`
- `mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_57`
- `mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_60`
- `mgk.resource.xǁResourceGuardǁremove_created__mutmut_28`
- `mgk.resource.xǁResourceGuardǁremove_created__mutmut_31`
- `mgk.resource.xǁResourceGuardǁremove_created__mutmut_34`

### JSON_FLAG_FALSY (1)

json ensure_ascii/allow_nan flag changed to a falsy-or-unreachable value: ensure_ascii=None and allow_nan=None behave as False (runtime probe); allow_nan=True/removed is unreachable because _validate rejects all floats before json.dumps.

- `mgk.canonical.x_canonicalize__mutmut_16`

### NOOP (12)

mutant body textually identical to original (def-line only); behavior identical by construction; verified via AST source comparison for all 12 (ledger _scan 10/11, _load_checkpoint 5/6, _write_checkpoint 45/46, append 56/57; crypto b64u_decode 29/30, b64u_encode 6/7).

- `mgk.crypto.x_b64u_decode__mutmut_29`
- `mgk.crypto.x_b64u_decode__mutmut_30`
- `mgk.crypto.x_b64u_encode__mutmut_6`
- `mgk.crypto.x_b64u_encode__mutmut_7`
- `mgk.ledger.xǁAuditLedgerǁ_load_checkpoint__mutmut_5`
- `mgk.ledger.xǁAuditLedgerǁ_load_checkpoint__mutmut_6`
- `mgk.ledger.xǁAuditLedgerǁ_scan__mutmut_10`
- `mgk.ledger.xǁAuditLedgerǁ_scan__mutmut_11`
- `mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_45`
- `mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_46`
- `mgk.ledger.xǁAuditLedgerǁappend__mutmut_56`
- `mgk.ledger.xǁAuditLedgerǁappend__mutmut_57`

### RESOLVE_STRICT_ONLY (2)

Path.resolve(strict=...) changed; the root is verified via is_dir()/is_symlink() before resolve(), so strict=True vs strict=False/None produce the same resolved path for an existing directory.

- `mgk.resource.xǁResourceGuardǁ__init____mutmut_10`
- `mgk.resource.xǁResourceGuardǁ__init____mutmut_9`

### SQL_CASE_ONLY (29)

SQL keyword/identifier case change only (SQLite keywords and unquoted identifiers are case-insensitive); runtime probe confirms identical rows/errors.

- `mgk.state.xǁSecurityStateǁ_connect__mutmut_10`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_11`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_14`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_15`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_18`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_19`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_22`
- `mgk.state.xǁSecurityStateǁ_connect__mutmut_23`
- `mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_13`
- `mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_5`
- `mgk.state.xǁSecurityStateǁbump_epoch__mutmut_30`
- `mgk.state.xǁSecurityStateǁbump_epoch__mutmut_34`
- `mgk.state.xǁSecurityStateǁbump_epoch__mutmut_43`
- `mgk.state.xǁSecurityStateǁbump_epoch__mutmut_52`
- `mgk.state.xǁSecurityStateǁbump_epoch__mutmut_56`
- `mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_14`
- `mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_20`
- `mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_21`
- `mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_24`
- `mgk.state.xǁSecurityStateǁcurrent_epoch__mutmut_4`
- `mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_35`
- `mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_39`
- `mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_50`
- `mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_54`
- `mgk.state.xǁSecurityStateǁintegrity_check__mutmut_17`
- `mgk.state.xǁSecurityStateǁintegrity_check__mutmut_18`
- `mgk.state.xǁSecurityStateǁintegrity_check__mutmut_26`
- `mgk.state.xǁSecurityStateǁnonce_count__mutmut_4`
- `mgk.state.xǁSecurityStateǁnonce_count__mutmut_5`

## SURVIVED_KILLABLE families

- **ASSIGN_RHS**: 87
- **RAISE_ARGS**: 40
- **OTHER_TOKEN**: 27
- **CONDITION_CHANGE**: 26
- **OPERATOR_CHANGE:or**: 13
- **RETURN_CHANGE**: 6
- **CALL_ARG:_validate()**: 6
- **CALL_ARG:print()**: 6
- **OPERATOR_CHANGE:<**: 4
- **MULTI_BODY**: 4
- **REMOVED_STMT**: 3
- **SQL_CASE_ONLY**: 2
- **OPERATOR_CHANGE:and**: 2
- **DEFAULT_ARG**: 1

Each SURVIVED_KILLABLE mutant changes an observable behavior (exception message/args, assigned attribute or record field, branch condition, return value, operator, default argument, removed statement, or recursion argument). Exact per-mutant diff evidence is recorded in `mutation-v2-classification.json`.

## INDETERMINATE

None. Every mutant was evaluated (0 no-tests, 0 timeouts un-re-evaluated).

# Security-Sensitive Survivors (SURVIVED_KILLABLE)

- source classification: `/var/folders/bf/7f75557n44s0d89v_dx0l7cr0000gn/T/opencode/mgk-verify/mutmut-v03/v03-fresh-classification.json`
- TOTAL_SURVIVED_KILLABLE: **209**
- SECURITY_SENSITIVE_SURVIVORS: **104**
- NON_SECURITY_SURVIVORS: **105**
- UNIQUE_IDS: 209  DUPLICATES: 0
- SHA-256: `aede2195554683e241b07435305af34ee623f1e6ca50c5c7c5ed6ceffedf16d0`

| module | survivors |
|---|---|
| authority | 4 |
| canonical | 20 |
| executor | 10 |
| ledger | 11 |
| resource | 46 |
| saxp | 1 |
| state | 12 |

## Mutant records
### mgk.authority.xǁCapabilityAuthorityǁ_bind_resource__mutmut_2

- module: `authority`
- function: `xǁCapabilityAuthorityǁ_bind_resource`
- mutant index: `2`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityAuthorityǁ_bind_resource__mutmut_orig(self, request: ActionRequest) -> dict[str, object]:
+     def xǁCapabilityAuthorityǁ_bind_resource__mutmut_2(self, request: ActionRequest) -> dict[str, object]:
-             raise ResourceError(f"resource unavailable: {exc}") from exc
+             raise ResourceError(None) from exc
```

### mgk.authority.xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_30

- module: `authority`
- function: `xǁCapabilityAuthorityǁ_bind_resource_dispatch`
- mutant index: `30`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_orig(self, request: ActionRequest) -> dict[str, object]:
+     def xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_30(self, request: ActionRequest) -> dict[str, object]:
-                 raise SchemaError("create payload exceeds size limit")
+                 raise SchemaError(None)
```

### mgk.authority.xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_31

- module: `authority`
- function: `xǁCapabilityAuthorityǁ_bind_resource_dispatch`
- mutant index: `31`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_orig(self, request: ActionRequest) -> dict[str, object]:
+     def xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_31(self, request: ActionRequest) -> dict[str, object]:
-                 raise SchemaError("create payload exceeds size limit")
+                 raise SchemaError("XXcreate payload exceeds size limitXX")
```

### mgk.authority.xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_32

- module: `authority`
- function: `xǁCapabilityAuthorityǁ_bind_resource_dispatch`
- mutant index: `32`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `SQL_CASE_ONLY`

```diff
-     def xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_orig(self, request: ActionRequest) -> dict[str, object]:
+     def xǁCapabilityAuthorityǁ_bind_resource_dispatch__mutmut_32(self, request: ActionRequest) -> dict[str, object]:
-                 raise SchemaError("create payload exceeds size limit")
+                 raise SchemaError("CREATE PAYLOAD EXCEEDS SIZE LIMIT")
```

### mgk.canonical.x__validate__mutmut_12

- module: `canonical`
- function: `x__validate`
- mutant index: `12`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_12(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-         raise CanonicalizationError("document item limit exceeded")
+         raise CanonicalizationError("XXdocument item limit exceededXX")
```

### mgk.canonical.x__validate__mutmut_36

- module: `canonical`
- function: `x__validate`
- mutant index: `36`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `OPERATOR_CHANGE:<`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_36(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-         if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
+         if any(0xD800 <= ord(char) < 0xDFFF for char in value):
```

### mgk.canonical.x__validate__mutmut_37

- module: `canonical`
- function: `x__validate`
- mutant index: `37`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `OPERATOR_CHANGE:<=`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_37(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-         if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
+         if any(0xD800 <= ord(char) <= 57344 for char in value):
```

### mgk.canonical.x__validate__mutmut_58

- module: `canonical`
- function: `x__validate`
- mutant index: `58`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_58(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(key, depth + 1, budget)
+             _validate(None, depth + 1, budget)
```

### mgk.canonical.x__validate__mutmut_60

- module: `canonical`
- function: `x__validate`
- mutant index: `60`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_60(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(key, depth + 1, budget)
+             _validate(key, depth + 1, None)
```

### mgk.canonical.x__validate__mutmut_63

- module: `canonical`
- function: `x__validate`
- mutant index: `63`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_63(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(key, depth + 1, budget)
+             _validate(key, depth + 1, )
```

### mgk.canonical.x__validate__mutmut_64

- module: `canonical`
- function: `x__validate`
- mutant index: `64`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_64(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(key, depth + 1, budget)
+             _validate(key, depth - 1, budget)
```

### mgk.canonical.x__validate__mutmut_65

- module: `canonical`
- function: `x__validate`
- mutant index: `65`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_65(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(key, depth + 1, budget)
+             _validate(key, depth + 2, budget)
```

### mgk.canonical.x__validate__mutmut_68

- module: `canonical`
- function: `x__validate`
- mutant index: `68`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_68(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(item, depth + 1, budget)
+             _validate(item, depth + 1, None)
```

### mgk.canonical.x__validate__mutmut_71

- module: `canonical`
- function: `x__validate`
- mutant index: `71`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_71(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(item, depth + 1, budget)
+             _validate(item, depth + 1, )
```

### mgk.canonical.x__validate__mutmut_72

- module: `canonical`
- function: `x__validate`
- mutant index: `72`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_72(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(item, depth + 1, budget)
+             _validate(item, depth - 1, budget)
```

### mgk.canonical.x__validate__mutmut_73

- module: `canonical`
- function: `x__validate`
- mutant index: `73`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x__validate__mutmut_orig(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
+ def x__validate__mutmut_73(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
-             _validate(item, depth + 1, budget)
+             _validate(item, depth + 2, budget)
```

### mgk.canonical.x_canonicalize__mutmut_26

- module: `canonical`
- function: `x_canonicalize`
- mutant index: `26`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `OTHER_TOKEN`

```diff
- def x_canonicalize__mutmut_orig(value: Any) -> bytes:
+ def x_canonicalize__mutmut_26(value: Any) -> bytes:
-         ).encode("utf-8", "strict")
+         ).encode("utf-8", "XXstrictXX")
```

### mgk.canonical.x_canonicalize__mutmut_28

- module: `canonical`
- function: `x_canonicalize`
- mutant index: `28`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
- def x_canonicalize__mutmut_orig(value: Any) -> bytes:
+ def x_canonicalize__mutmut_28(value: Any) -> bytes:
-         raise CanonicalizationError(str(exc)) from exc
+         raise CanonicalizationError(None) from exc
```

### mgk.canonical.x_canonicalize__mutmut_29

- module: `canonical`
- function: `x_canonicalize`
- mutant index: `29`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
- def x_canonicalize__mutmut_orig(value: Any) -> bytes:
+ def x_canonicalize__mutmut_29(value: Any) -> bytes:
-         raise CanonicalizationError(str(exc)) from exc
+         raise CanonicalizationError(str(None)) from exc
```

### mgk.canonical.x_parse_canonical__mutmut_14

- module: `canonical`
- function: `x_parse_canonical`
- mutant index: `14`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
- def x_parse_canonical__mutmut_orig(data: bytes) -> Any:
+ def x_parse_canonical__mutmut_14(data: bytes) -> Any:
-         text = data.decode("utf-8", "strict")
+         text = data.decode("utf-8", )
```

### mgk.canonical.x_parse_canonical__mutmut_28

- module: `canonical`
- function: `x_parse_canonical`
- mutant index: `28`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
- def x_parse_canonical__mutmut_orig(data: bytes) -> Any:
+ def x_parse_canonical__mutmut_28(data: bytes) -> Any:
-         raise CanonicalizationError(str(exc)) from exc
+         raise CanonicalizationError(None) from exc
```

### mgk.canonical.x_parse_canonical__mutmut_29

- module: `canonical`
- function: `x_parse_canonical`
- mutant index: `29`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
- def x_parse_canonical__mutmut_orig(data: bytes) -> Any:
+ def x_parse_canonical__mutmut_29(data: bytes) -> Any:
-         raise CanonicalizationError(str(exc)) from exc
+         raise CanonicalizationError(str(None)) from exc
```

### mgk.canonical.x_parse_canonical__mutmut_30

- module: `canonical`
- function: `x_parse_canonical`
- mutant index: `30`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CALL_ARG:_validate()`

```diff
- def x_parse_canonical__mutmut_orig(data: bytes) -> Any:
+ def x_parse_canonical__mutmut_30(data: bytes) -> Any:
-     _validate(value)
+     _validate(None)
```

### mgk.canonical.x_parse_canonical__mutmut_6

- module: `canonical`
- function: `x_parse_canonical`
- mutant index: `6`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `OPERATOR_CHANGE:or`

```diff
- def x_parse_canonical__mutmut_orig(data: bytes) -> Any:
-     if type(data) is not bytes or not data or len(data) > MAX_CANONICAL_BYTES:
+ def x_parse_canonical__mutmut_6(data: bytes) -> Any:
+     if type(data) is not bytes or not data or len(data) >= MAX_CANONICAL_BYTES:
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_12

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `12`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_12(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-             payload = self.verifier.verify(envelope_bytes, request, consume_nonce=True)
+             payload = self.verifier.verify(envelope_bytes, request, )
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_124

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `124`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_124(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise ValueError("unsupported executor action")
+                 raise ValueError(None)
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_125

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `125`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_125(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise ValueError("unsupported executor action")
+                 raise ValueError("XXunsupported executor actionXX")
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_126

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `126`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_126(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise ValueError("unsupported executor action")
+                 raise ValueError("UNSUPPORTED EXECUTOR ACTION")
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_3

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `3`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_3(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise ValueError("executor audience mismatch")
+                 raise ValueError(None)
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_37

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `37`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_37(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise EpochError("authorization epoch changed before commit")
+                 raise EpochError(None)
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_38

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `38`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_38(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise EpochError("authorization epoch changed before commit")
+                 raise EpochError("XXauthorization epoch changed before commitXX")
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_39

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `39`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_39(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise EpochError("authorization epoch changed before commit")
+                 raise EpochError("AUTHORIZATION EPOCH CHANGED BEFORE COMMIT")
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_4

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `4`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_4(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise ValueError("executor audience mismatch")
+                 raise ValueError("XXexecutor audience mismatchXX")
```

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_5

- module: `executor`
- function: `xǁCapabilityExecutorǁexecute`
- mutant index: `5`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁCapabilityExecutorǁexecute__mutmut_orig(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
+     def xǁCapabilityExecutorǁexecute__mutmut_5(self, envelope_bytes: bytes, request: ActionRequest) -> ExecutionResult:
-                 raise ValueError("executor audience mismatch")
+                 raise ValueError("EXECUTOR AUDIENCE MISMATCH")
```

### mgk.ledger.xǁAuditLedgerǁ__init____mutmut_28

- module: `ledger`
- function: `xǁAuditLedgerǁ__init__`
- mutant index: `28`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ__init____mutmut_orig(
+     def xǁAuditLedgerǁ__init____mutmut_28(
-             self.ledger_path.touch(mode=0o600, exist_ok=False)
+             self.ledger_path.touch(mode=0o600, exist_ok=None)
```

### mgk.ledger.xǁAuditLedgerǁ__init____mutmut_30

- module: `ledger`
- function: `xǁAuditLedgerǁ__init__`
- mutant index: `30`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ__init____mutmut_orig(
+     def xǁAuditLedgerǁ__init____mutmut_30(
-             self.ledger_path.touch(mode=0o600, exist_ok=False)
+             self.ledger_path.touch(mode=0o600, )
```

### mgk.ledger.xǁAuditLedgerǁ__init____mutmut_32

- module: `ledger`
- function: `xǁAuditLedgerǁ__init__`
- mutant index: `32`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ__init____mutmut_orig(
+     def xǁAuditLedgerǁ__init____mutmut_32(
-             self.ledger_path.touch(mode=0o600, exist_ok=False)
+             self.ledger_path.touch(mode=0o600, exist_ok=True)
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_2

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `2`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_2(self, count: int, head_hash: str, updated_at: int) -> None:
-             raise AuditIntegrityError("ledger is verify-only")
+             raise AuditIntegrityError(None)
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_3

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `3`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_3(self, count: int, head_hash: str, updated_at: int) -> None:
-             raise AuditIntegrityError("ledger is verify-only")
+             raise AuditIntegrityError("XXledger is verify-onlyXX")
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_4

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `4`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_4(self, count: int, head_hash: str, updated_at: int) -> None:
-             raise AuditIntegrityError("ledger is verify-only")
+             raise AuditIntegrityError("LEDGER IS VERIFY-ONLY")
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_57

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `57`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_57(self, count: int, head_hash: str, updated_at: int) -> None:
-             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
+             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY & getattr(os, "O_DIRECTORY", 0))
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_58

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `58`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_58(self, count: int, head_hash: str, updated_at: int) -> None:
-             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
+             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(None, "O_DIRECTORY", 0))
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_64

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `64`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_64(self, count: int, head_hash: str, updated_at: int) -> None:
-             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
+             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "XXO_DIRECTORYXX", 0))
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_65

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `65`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_65(self, count: int, head_hash: str, updated_at: int) -> None:
-             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
+             directory = os.open(self.checkpoint_path.parent, os.O_RDONLY | getattr(os, "o_directory", 0))
```

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_70

- module: `ledger`
- function: `xǁAuditLedgerǁ_write_checkpoint`
- mutant index: `70`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `OTHER_TOKEN`

```diff
-     def xǁAuditLedgerǁ_write_checkpoint__mutmut_orig(self, count: int, head_hash: str, updated_at: int) -> None:
+     def xǁAuditLedgerǁ_write_checkpoint__mutmut_70(self, count: int, head_hash: str, updated_at: int) -> None:
-                 os.unlink(temporary)
+                 os.unlink(None)
```

### mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_17

- module: `resource`
- function: `xǁResourceGuardǁ_open_parent`
- mutant index: `17`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁ_open_parent__mutmut_orig(self, relative: str) -> tuple[int, str]:
+     def xǁResourceGuardǁ_open_parent__mutmut_17(self, relative: str) -> tuple[int, str]:
-         flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
+         flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", None)
```

### mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_20

- module: `resource`
- function: `xǁResourceGuardǁ_open_parent`
- mutant index: `20`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁ_open_parent__mutmut_orig(self, relative: str) -> tuple[int, str]:
+     def xǁResourceGuardǁ_open_parent__mutmut_20(self, relative: str) -> tuple[int, str]:
-         flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
+         flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", )
```

### mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_23

- module: `resource`
- function: `xǁResourceGuardǁ_open_parent`
- mutant index: `23`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁ_open_parent__mutmut_orig(self, relative: str) -> tuple[int, str]:
+     def xǁResourceGuardǁ_open_parent__mutmut_23(self, relative: str) -> tuple[int, str]:
-         flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
+         flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 1)
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_105

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `105`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_105(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("appended resource verification failed")
+                 raise ResourceError(None)
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_106

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `106`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_106(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("appended resource verification failed")
+                 raise ResourceError("XXappended resource verification failedXX")
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_107

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `107`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_107(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("appended resource verification failed")
+                 raise ResourceError("APPENDED RESOURCE VERIFICATION FAILED")
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_109

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `109`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_109(self, binding: dict[str, object], data: bytes) -> str:
-             descriptor = None
+             descriptor = ""
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_59

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `59`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_59(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("append target is not a regular file")
+                 raise ResourceError(None)
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_60

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `60`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_60(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("append target is not a regular file")
+                 raise ResourceError("XXappend target is not a regular fileXX")
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_61

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `61`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_61(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("append target is not a regular file")
+                 raise ResourceError("APPEND TARGET IS NOT A REGULAR FILE")
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_93

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `93`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_93(self, binding: dict[str, object], data: bytes) -> str:
-                     raise ResourceError("short write while appending resource")
+                     raise ResourceError("XXshort write while appending resourceXX")
```

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_99

- module: `resource`
- function: `xǁResourceGuardǁappend_bound`
- mutant index: `99`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CONDITION_CHANGE`

```diff
-     def xǁResourceGuardǁappend_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁappend_bound__mutmut_99(self, binding: dict[str, object], data: bytes) -> str:
-             if not stat.S_ISREG(info.st_mode) or info.st_size != binding["post_size"]:
+             if not stat.S_ISREG(info.st_mode) and info.st_size != binding["post_size"]:
```

### mgk.resource.xǁResourceGuardǁbind_absent__mutmut_20

- module: `resource`
- function: `xǁResourceGuardǁbind_absent`
- mutant index: `20`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁbind_absent__mutmut_orig(self, relative: str, post_sha256: str, post_size: int) -> dict[str, object]:
+     def xǁResourceGuardǁbind_absent__mutmut_20(self, relative: str, post_sha256: str, post_size: int) -> dict[str, object]:
-                 os.stat(name, dir_fd=parent, follow_symlinks=False)
+                 os.stat(name, dir_fd=parent, follow_symlinks=None)
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_38

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `38`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_38(self, binding: dict[str, object], data: bytes) -> str:
-             raise ResourceError("create payload exceeds size limit")
+             raise ResourceError(None)
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_39

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `39`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_39(self, binding: dict[str, object], data: bytes) -> str:
-             raise ResourceError("create payload exceeds size limit")
+             raise ResourceError("XXcreate payload exceeds size limitXX")
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_40

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `40`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `SQL_CASE_ONLY`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_40(self, binding: dict[str, object], data: bytes) -> str:
-             raise ResourceError("create payload exceeds size limit")
+             raise ResourceError("CREATE PAYLOAD EXCEEDS SIZE LIMIT")
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_46

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `46`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_46(self, binding: dict[str, object], data: bytes) -> str:
-         created = False
+         created = None
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_47

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `47`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_47(self, binding: dict[str, object], data: bytes) -> str:
-         created = False
+         created = True
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_52

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `52`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_52(self, binding: dict[str, object], data: bytes) -> str:
-             flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
+             flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(None, "O_NOFOLLOW", 0)
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_58

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `58`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_58(self, binding: dict[str, object], data: bytes) -> str:
-             flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
+             flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "XXO_NOFOLLOWXX", 0)
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_59

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `59`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_59(self, binding: dict[str, object], data: bytes) -> str:
-             flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
+             flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "o_nofollow", 0)
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_83

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `83`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_83(self, binding: dict[str, object], data: bytes) -> str:
-                     raise ResourceError("short write while creating resource")
+                     raise ResourceError("XXshort write while creating resourceXX")
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_89

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `89`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CONDITION_CHANGE`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_89(self, binding: dict[str, object], data: bytes) -> str:
-             if not stat.S_ISREG(info.st_mode) or info.st_size != len(data):
+             if not stat.S_ISREG(info.st_mode) and info.st_size != len(data):
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_93

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `93`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_93(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("created resource verification failed")
+                 raise ResourceError(None)
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_94

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `94`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_94(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("created resource verification failed")
+                 raise ResourceError("XXcreated resource verification failedXX")
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_95

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `95`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_95(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("created resource verification failed")
+                 raise ResourceError("CREATED RESOURCE VERIFICATION FAILED")
```

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_97

- module: `resource`
- function: `xǁResourceGuardǁcreate_bound`
- mutant index: `97`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁcreate_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁcreate_bound__mutmut_97(self, binding: dict[str, object], data: bytes) -> str:
-             descriptor = None
+             descriptor = ""
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_125

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `125`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_125(self, binding: dict[str, object], data: bytes) -> str:
-                     raise ResourceError("write target is not a regular file")
+                     raise ResourceError(None)
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_126

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `126`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_126(self, binding: dict[str, object], data: bytes) -> str:
-                     raise ResourceError("write target is not a regular file")
+                     raise ResourceError("XXwrite target is not a regular fileXX")
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_127

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `127`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_127(self, binding: dict[str, object], data: bytes) -> str:
-                     raise ResourceError("write target is not a regular file")
+                     raise ResourceError("WRITE TARGET IS NOT A REGULAR FILE")
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_164

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `164`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_164(self, binding: dict[str, object], data: bytes) -> str:
-                     raise ResourceError("short write while writing resource")
+                     raise ResourceError("XXshort write while writing resourceXX")
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_170

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `170`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `CONDITION_CHANGE`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_170(self, binding: dict[str, object], data: bytes) -> str:
-             if not stat.S_ISREG(info.st_mode) or info.st_size != len(data):
+             if not stat.S_ISREG(info.st_mode) and info.st_size != len(data):
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_174

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `174`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_174(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("written resource verification failed")
+                 raise ResourceError(None)
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_175

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `175`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_175(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("written resource verification failed")
+                 raise ResourceError("XXwritten resource verification failedXX")
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_176

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `176`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_176(self, binding: dict[str, object], data: bytes) -> str:
-                 raise ResourceError("written resource verification failed")
+                 raise ResourceError("WRITTEN RESOURCE VERIFICATION FAILED")
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_178

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `178`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_178(self, binding: dict[str, object], data: bytes) -> str:
-             descriptor = None
+             descriptor = ""
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_180

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `180`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_180(self, binding: dict[str, object], data: bytes) -> str:
-             raise ResourceError("write target appeared after authorization") from exc
+             raise ResourceError(None) from exc
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_181

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `181`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_181(self, binding: dict[str, object], data: bytes) -> str:
-             raise ResourceError("write target appeared after authorization") from exc
+             raise ResourceError("XXwrite target appeared after authorizationXX") from exc
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_182

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `182`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `SQL_CASE_ONLY`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_182(self, binding: dict[str, object], data: bytes) -> str:
-             raise ResourceError("write target appeared after authorization") from exc
+             raise ResourceError("WRITE TARGET APPEARED AFTER AUTHORIZATION") from exc
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_61

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `61`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_61(self, binding: dict[str, object], data: bytes) -> str:
-         created = False
+         created = None
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_70

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `70`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_70(self, binding: dict[str, object], data: bytes) -> str:
-                     os.stat(name, dir_fd=parent, follow_symlinks=False)
+                     os.stat(name, dir_fd=parent, follow_symlinks=None)
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_73

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `73`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_73(self, binding: dict[str, object], data: bytes) -> str:
-                     os.stat(name, dir_fd=parent, follow_symlinks=False)
+                     os.stat(name, dir_fd=parent, )
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_74

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `74`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_74(self, binding: dict[str, object], data: bytes) -> str:
-                     os.stat(name, dir_fd=parent, follow_symlinks=False)
+                     os.stat(name, dir_fd=parent, follow_symlinks=True)
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_82

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `82`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_82(self, binding: dict[str, object], data: bytes) -> str:
-                 flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
+                 flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(None, "O_NOFOLLOW", 0)
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_88

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `88`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_88(self, binding: dict[str, object], data: bytes) -> str:
-                 flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
+                 flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "XXO_NOFOLLOWXX", 0)
```

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_89

- module: `resource`
- function: `xǁResourceGuardǁwrite_bound`
- mutant index: `89`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁResourceGuardǁwrite_bound__mutmut_orig(self, binding: dict[str, object], data: bytes) -> str:
+     def xǁResourceGuardǁwrite_bound__mutmut_89(self, binding: dict[str, object], data: bytes) -> str:
-                 flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
+                 flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "o_nofollow", 0)
```

### mgk.saxp.xǁSAXPEvaluatorǁ__init____mutmut_15

- module: `saxp`
- function: `xǁSAXPEvaluatorǁ__init__`
- mutant index: `15`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `OPERATOR_CHANGE:<`

```diff
-     def xǁSAXPEvaluatorǁ__init____mutmut_orig(self, policy_id: str = "saxp-level1-v1", minimum_sentidino: int = 5000):
+     def xǁSAXPEvaluatorǁ__init____mutmut_15(self, policy_id: str = "saxp-level1-v1", minimum_sentidino: int = 5000):
-         if not 0 <= minimum_sentidino <= 10000:
+         if not 0 <= minimum_sentidino < 10000:
```

### mgk.state.xǁSecurityStateǁ_connect__mutmut_5

- module: `state`
- function: `xǁSecurityStateǁ_connect`
- mutant index: `5`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁSecurityStateǁ_connect__mutmut_orig(self) -> sqlite3.Connection:
-         connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
+     def xǁSecurityStateǁ_connect__mutmut_5(self) -> sqlite3.Connection:
+         connection = sqlite3.connect(self.path, isolation_level=None)
```

### mgk.state.xǁSecurityStateǁ_connect__mutmut_7

- module: `state`
- function: `xǁSecurityStateǁ_connect`
- mutant index: `7`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `ASSIGN_RHS`

```diff
-     def xǁSecurityStateǁ_connect__mutmut_orig(self) -> sqlite3.Connection:
-         connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
+     def xǁSecurityStateǁ_connect__mutmut_7(self) -> sqlite3.Connection:
+         connection = sqlite3.connect(self.path, timeout=31, isolation_level=None)
```

### mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_28

- module: `state`
- function: `xǁSecurityStateǁ_ensure_schema`
- mutant index: `28`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁ_ensure_schema__mutmut_orig(self) -> None:
+     def xǁSecurityStateǁ_ensure_schema__mutmut_28(self) -> None:
-             raise StateIntegrityError(f"security state initialization failed: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁbump_epoch__mutmut_45

- module: `state`
- function: `xǁSecurityStateǁbump_epoch`
- mutant index: `45`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁbump_epoch__mutmut_orig(self, signer: Ed25519PrivateKey) -> int:
+     def xǁSecurityStateǁbump_epoch__mutmut_45(self, signer: Ed25519PrivateKey) -> int:
-                     raise EpochError("epoch changed concurrently")
+                     raise EpochError("XXepoch changed concurrentlyXX")
```

### mgk.state.xǁSecurityStateǁbump_epoch__mutmut_57

- module: `state`
- function: `xǁSecurityStateǁbump_epoch`
- mutant index: `57`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁbump_epoch__mutmut_orig(self, signer: Ed25519PrivateKey) -> int:
+     def xǁSecurityStateǁbump_epoch__mutmut_57(self, signer: Ed25519PrivateKey) -> int:
-             raise StateIntegrityError(f"cannot bump epoch: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_28

- module: `state`
- function: `xǁSecurityStateǁconsume_nonce`
- mutant index: `28`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁconsume_nonce__mutmut_orig(self, nonce: str, capability_id: str, consumed_at: int) -> None:
+     def xǁSecurityStateǁconsume_nonce__mutmut_28(self, nonce: str, capability_id: str, consumed_at: int) -> None:
-             raise StateIntegrityError(f"cannot consume nonce: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁcurrent_epoch__mutmut_6

- module: `state`
- function: `xǁSecurityStateǁcurrent_epoch`
- mutant index: `6`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁcurrent_epoch__mutmut_orig(self) -> int:
+     def xǁSecurityStateǁcurrent_epoch__mutmut_6(self) -> int:
-             raise StateIntegrityError(f"cannot read epoch: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_55

- module: `state`
- function: `xǁSecurityStateǁinitialize_epoch`
- mutant index: `55`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁinitialize_epoch__mutmut_orig(self, epoch: int, signer: Ed25519PrivateKey) -> None:
+     def xǁSecurityStateǁinitialize_epoch__mutmut_55(self, epoch: int, signer: Ed25519PrivateKey) -> None:
-             raise StateIntegrityError(f"cannot initialize epoch: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁintegrity_check__mutmut_13

- module: `state`
- function: `xǁSecurityStateǁintegrity_check`
- mutant index: `13`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁintegrity_check__mutmut_orig(self) -> None:
+     def xǁSecurityStateǁintegrity_check__mutmut_13(self) -> None:
-             raise StateIntegrityError(f"security state file is unreadable: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁintegrity_check__mutmut_22

- module: `state`
- function: `xǁSecurityStateǁintegrity_check`
- mutant index: `22`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁintegrity_check__mutmut_orig(self) -> None:
+     def xǁSecurityStateǁintegrity_check__mutmut_22(self) -> None:
-                     raise StateIntegrityError(f"SQLite integrity check failed: {result}")
+                     raise StateIntegrityError(None)
```

### mgk.state.xǁSecurityStateǁintegrity_check__mutmut_36

- module: `state`
- function: `xǁSecurityStateǁintegrity_check`
- mutant index: `36`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁintegrity_check__mutmut_orig(self) -> None:
+     def xǁSecurityStateǁintegrity_check__mutmut_36(self) -> None:
-             raise StateIntegrityError(f"security state is unreadable: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```

### mgk.state.xǁSecurityStateǁnonce_count__mutmut_7

- module: `state`
- function: `xǁSecurityStateǁnonce_count`
- mutant index: `7`
- run status: `survived`
- classification: `SURVIVED_KILLABLE`
- family: `RAISE_ARGS`

```diff
-     def xǁSecurityStateǁnonce_count__mutmut_orig(self) -> int:
+     def xǁSecurityStateǁnonce_count__mutmut_7(self) -> int:
-             raise StateIntegrityError(f"cannot count nonces: {exc}") from exc
+             raise StateIntegrityError(None) from exc
```


# Sensitive Survivor Security Classification (with phase 4 dispositions)

- source: `/Users/iagoveloso/mgk-governance-kernel/evidence/v0.3.0/security-mutation-adequacy/sensitive-survivor-classification.json`
- disposition reference: `/Users/iagoveloso/mgk-governance-kernel/evidence/v0.2.0/security-mutation-adequacy/sensitive-survivor-classification.json`
- phase4 dispositions applied: **33**
- SHA-256: `b9bbaff9aed041b25a93dd5acdeafeea3331119f8fb1abc37541e0e80526b460`

## Counts by security class

| class | count |
|---|---|
| AVAILABILITY_ONLY | 52 |
| EQUIVALENT_PROVEN | 3 |
| INTEGRITY_WEAKENING | 30 |
| SECURITY_BYPASS | 3 |
| TEST_GAP_ONLY | 16 |

## Counts by phase4 disposition

- AVAILABILITY_ONLY: 1
- EQUIVALENT_PROVEN: 31
- NOT_TARGET: 71
- TEST_GAP_ONLY: 1

### mgk.canonical.x_parse_canonical__mutmut_14

- module: `canonical`  function: `x_parse_canonical`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.canonical.x_parse_canonical__mutmut_14): data.decode('utf-8', ) drops the explicit errors='strict'; str.decode default errors is 'strict', so behavior is identical (verified: all canonical tests pass on the mutant).

### mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_12

- module: `executor`  function: `xǁCapabilityExecutorǁexecute`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.executor.xǁCapabilityExecutorǁexecute__mutmut_12): Removed consume_nonce=True kwarg; CapabilityVerifier.verify default is consume_nonce=True (src/mgk/verifier.py:130). test_executor_rejects_replayed_envelope executes the mutant copy and proves the nonce is still consumed (replay still DENIED with REPLAY_ERROR).

### mgk.ledger.xǁAuditLedgerǁ__init____mutmut_28

- module: `ledger`  function: `xǁAuditLedgerǁ__init__`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ__init____mutmut_28): touch(mode=0o600, exist_ok=None) — None is falsy like False, and touch only runs on first init when both ledger and checkpoint files are absent, so the file is created identically; the partial-state path raises AuditIntegrityError before touch regardless of exist_ok.

### mgk.ledger.xǁAuditLedgerǁ__init____mutmut_30

- module: `ledger`  function: `xǁAuditLedgerǁ__init__`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ__init____mutmut_30): touch exist_ok kwarg removed (default True). Only runs on first init when both files are absent, so creation is identical; partial-state path raises AuditIntegrityError regardless.

### mgk.ledger.xǁAuditLedgerǁ__init____mutmut_32

- module: `ledger`  function: `xǁAuditLedgerǁ__init__`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ__init____mutmut_32): touch(mode=0o600, exist_ok=True). Only runs on first init when both files are absent; creation identical; partial-state path raises AuditIntegrityError regardless.

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_57

- module: `ledger`  function: `xǁAuditLedgerǁ_write_checkpoint`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_57): os.O_RDONLY & os.O_DIRECTORY = 0 (O_RDONLY is 0). os.mkstemp(dir=self.checkpoint_path.parent) runs first and would raise NotADirectoryError if the parent were not a real directory, so the os.open line always opens a real directory where O_RDONLY and O_RDONLY|O_DIRECTORY behave identically.

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_58

- module: `ledger`  function: `xǁAuditLedgerǁ_write_checkpoint`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_58): getattr(None,"O_DIRECTORY",0) -> 0; the parent is always a real directory at this point (mkstemp guard), so opening it with or without O_DIRECTORY is identical.

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_64

- module: `ledger`  function: `xǁAuditLedgerǁ_write_checkpoint`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_64): getattr(os,"XXO_DIRECTORYXX",0) -> 0; parent always a real directory (mkstemp guard), identical behavior.

### mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_65

- module: `ledger`  function: `xǁAuditLedgerǁ_write_checkpoint`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.ledger.xǁAuditLedgerǁ_write_checkpoint__mutmut_65): getattr(os,"o_directory",0) -> 0; parent always a real directory (mkstemp guard), identical behavior.

### mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_17

- module: `resource`  function: `xǁResourceGuardǁ_open_parent`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_17): getattr(os,"O_DIRECTORY",None): os.O_DIRECTORY exists on this platform so the default None is never used and flags are identical (verified: bind_present succeeds identically on the mutant).

### mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_20

- module: `resource`  function: `xǁResourceGuardǁ_open_parent`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_20): getattr(os,"O_NOFOLLOW",) with no default returns os.O_NOFOLLOW (it exists on this platform), so flags are identical (verified empirically).

### mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_23

- module: `resource`  function: `xǁResourceGuardǁ_open_parent`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `AVAILABILITY_ONLY`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁ_open_parent__mutmut_23): getattr default changed to 1: the resulting flags include the O_WRONLY bit, so opening the parent directory fails with ENOTDIR and every resource operation fails closed (verified: bind_present raises NotADirectoryError). No confidentiality or integrity bypass.

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_109

- module: `resource`  function: `xǁResourceGuardǁappend_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁappend_bound__mutmut_109): descriptor sentinel "" instead of None only at the post-close assignment (descriptor=None after os.close). Only an unreachable os.fsync(parent) EIO could observe it; the success path returns the identical digest.

### mgk.resource.xǁResourceGuardǁappend_bound__mutmut_99

- module: `resource`  function: `xǁResourceGuardǁappend_bound`
- security class: `SECURITY_BYPASS`  family: `CONDITION_CHANGE`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁappend_bound__mutmut_99): Post-append verification "or"->"and". The write loop only exits with an empty view (short writes raise), so size==post_size and S_ISREG hold on every success path; the check cannot diverge in isolation (the partial-write variant was killed as mutmut_95).

### mgk.resource.xǁResourceGuardǁbind_absent__mutmut_20

- module: `resource`  function: `xǁResourceGuardǁbind_absent`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁbind_absent__mutmut_20): os.stat(follow_symlinks=None) is treated as lstat (None is falsy; verified empirically on this platform), identical to follow_symlinks=False; symlink targets are still rejected.

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_46

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_46): created=False->None: None is falsy like False, and create_bound unconditionally assigns created=True after os.open succeeds, so there is no observable difference.

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_47

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `TEST_GAP_ONLY`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_47): created=False->True: the extra unlink only differs for non-EEXIST/EACCES os.open failures (e.g. fd exhaustion racing a target appearance), where the mutant attempts os.unlink of the raced-in file while the original does not. Not deterministically reachable; on reachable inputs both raise the same OSError.

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_52

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_52): O_NOFOLLOW dropped via getattr(None,...). os.open uses O_CREAT|O_EXCL, so any pre-existing target (including a symlink) yields EEXIST -> FileExistsError -> ResourceError("create target appeared after authorization") identically; O_NOFOLLOW is redundant behind O_EXCL.

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_58

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_58): O_NOFOLLOW dropped via misspelled attr -> 0; O_EXCL still forces EEXIST for any pre-existing target identically.

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_59

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_59): O_NOFOLLOW dropped via lowercase attr -> 0; O_EXCL still forces EEXIST for any pre-existing target identically.

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_89

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `SECURITY_BYPASS`  family: `CONDITION_CHANGE`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_89): Post-create verification "or"->"and". The write loop guarantees size==len(data) on success (short writes raise), so the check cannot diverge in isolation (the partial-write variant was killed as mutmut_85).

### mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_97

- module: `resource`  function: `xǁResourceGuardǁcreate_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁcreate_bound__mutmut_97): descriptor sentinel "" after os.close; only an unreachable os.fsync(parent) EIO could observe it; success path identical.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_170

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `SECURITY_BYPASS`  family: `CONDITION_CHANGE`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_170): Post-write verification "or"->"and". The write loop guarantees size==len(data) on success, so the check cannot diverge in isolation (the partial-write variant was killed as mutmut_166).

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_178

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_178): descriptor sentinel "" after os.close; only an unreachable os.fsync(parent) EIO could observe it; success path identical.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_61

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_61): created=False->None: None is falsy like False, and write_bound unconditionally assigns created=True after os.open succeeds; no observable difference.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_70

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_70): os.stat(follow_symlinks=None) is treated as lstat (verified empirically); identical to follow_symlinks=False.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_73

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_73): follow_symlinks kwarg removed (default True). With a dangling symlink the mutant proceeds to os.open, which uses O_CREAT|O_EXCL|O_NOFOLLOW -> EEXIST -> ResourceError("write target appeared after authorization"), identical to the original stat rejection (verified: test_resource_write_rejects_dangling_symlink_target passes on the mutant).

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_74

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_74): follow_symlinks=True. Same fail-closed outcome as 73: os.open O_CREAT|O_EXCL on the raced-in symlink yields EEXIST -> ResourceError identically.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_82

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_82): O_NOFOLLOW dropped via getattr(None,...) in the absent-branch open. The stat re-check (follow_symlinks=False) rejects symlinks before the open, and O_EXCL still makes any raced-in target EEXIST -> ResourceError("write target appeared after authorization") identically.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_88

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_88): O_NOFOLLOW dropped via misspelled attr -> 0; stat re-check + O_EXCL still reject symlinks/raced targets identically.

### mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_89

- module: `resource`  function: `xǁResourceGuardǁwrite_bound`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.resource.xǁResourceGuardǁwrite_bound__mutmut_89): O_NOFOLLOW dropped via lowercase attr -> 0; stat re-check + O_EXCL still reject symlinks/raced targets identically.

### mgk.state.xǁSecurityStateǁ_connect__mutmut_5

- module: `state`  function: `xǁSecurityStateǁ_connect`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.state.xǁSecurityStateǁ_connect__mutmut_5): EQUIVALENT_PROVEN: sqlite3.connect(timeout=30) is immediately overridden by PRAGMA busy_timeout=30000 inside _connect (state.py:33-37), so removing the timeout kwarg (default 5s) has no effect on the effective busy timeout. Verified: test_security_state_busy_timeout_is_pragma_30000 passes identically on the mutant copy.

### mgk.state.xǁSecurityStateǁ_connect__mutmut_7

- module: `state`  function: `xǁSecurityStateǁ_connect`
- security class: `INTEGRITY_WEAKENING`  family: `ASSIGN_RHS`
- phase4 disposition: `EQUIVALENT_PROVEN`

carried from v0.2.0 security-mutation-adequacy evidence (diff-identical mutant mgk.state.xǁSecurityStateǁ_connect__mutmut_7): EQUIVALENT_PROVEN: sqlite3.connect timeout 30->31s is immediately overridden by PRAGMA busy_timeout=30000 inside _connect; the effective busy timeout is identical. Verified: test_security_state_busy_timeout_is_pragma_30000 passes identically on the mutant copy.


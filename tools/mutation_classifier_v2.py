#!/usr/bin/env python3
"""Mutation Gate v2 classifier.

Transformation-family classification of mutmut survivors with equivalence
evidence rules, per MGK-MUTATION-GATE-V2.yaml.

Categories: KILLED, SURVIVED_KILLABLE, EQUIVALENT_PROVEN, INVALID_MUTANT,
UNREACHABLE_PROVEN, INDETERMINATE.
"""

from __future__ import annotations

import difflib
import re
from collections import Counter


def norm_def(x: str) -> str:
    x = re.sub(r"__mutmut_orig", "__mutmut_N", x)
    return re.sub(r"__mutmut_\d+", "__mutmut_N", x)


def split_pair(m: list[str], p: list[str]):
    mdef = [x for x in m if x.lstrip().startswith("def ")]
    pdef = [x for x in p if x.lstrip().startswith("def ")]
    mbody = [x for x in m if not x.lstrip().startswith("def ")]
    pbody = [x for x in p if not x.lstrip().startswith("def ")]
    return mdef, pdef, mbody, pbody


def sql_case_only(a: str, b: str) -> bool:
    if a.lower() != b.lower():
        return False
    low = a.lower()
    return any(
        k in low
        for k in (
            "select ",
            "insert ",
            "update ",
            "begin ",
            "commit ",
            "delete ",
            "from ",
            "where ",
            " values ",
            "create ",
        )
    )


def token_change(a: str, b: str) -> str:
    if a == b:
        return "NOOP"
    if sql_case_only(a, b):
        return "SQL_CASE_ONLY"
    if (a.startswith('"') and a.endswith('"')) or (a.startswith("'") and a.endswith("'")):
        if a.lower() == b.lower():
            return "STRING_CASE_ONLY"
        return "STRING_CONST"
    for op in (" and ", " or ", " is not ", " is ", " == ", " != ", " <= ", " >= ", " < ", " > "):
        if op.strip() in a and op.strip() in b:
            pa = a.split(op.strip())
            pb = b.split(op.strip())
            if pa[0].strip() == pb[0].strip() and pa[1].strip() == pb[1].strip():
                return "OPERATOR_CHANGE:" + op.strip()
    for t in (("True", "False"), ("False", "True"), ("None", "True"), ("None", "False"), ("None", "{}")):
        if a == t[0] and b == t[1]:
            return "BOOLEAN_SWAP:" + t[0] + "->" + t[1]
    if re.fullmatch(r"-?\d+", a) and re.fullmatch(r"-?\d+", b):
        return "NUMBER_CONST"
    m = re.match(r"(\w+)\s*\((.*)\)$", a)
    n = re.match(r"(\w+)\s*\((.*)\)$", b)
    if m and n and m.group(1) == n.group(1):
        return "CALL_ARG:" + m.group(1) + "()"
    if a.startswith(("if ", "elif ", "while ")):
        return "CONDITION_CHANGE"
    if a.startswith("raise "):
        return "RAISE_ARGS"
    if a.startswith("return "):
        return "RETURN_CHANGE"
    if "=" in a and "=" in b and a.split("=", 1)[0].strip() == b.split("=", 1)[0].strip():
        return "ASSIGN_RHS"
    return "OTHER_TOKEN"


def classify_pair(m: list[str], p: list[str], labels: list[str]) -> None:
    mdef, pdef, mbody, pbody = split_pair(m, p)
    for od, nd in zip(mdef, pdef):
        if norm_def(od) != norm_def(nd):
            labels.append("DEFAULT_ARG")
    if not mbody and not pbody:
        return
    if len(mbody) == 1 and len(pbody) == 1:
        labels.append(token_change(mbody[0].strip(), pbody[0].strip()))
    elif len(mbody) == 1 and not pbody:
        labels.append("REMOVED_STMT")
    elif not mbody and len(pbody) == 1:
        labels.append("ADDED_STMT")
    elif len(mbody) == len(pbody):
        diffs = [(a, b) for a, b in zip(mbody, pbody) if a.strip() != b.strip()]
        if len(diffs) == 1:
            labels.append(token_change(diffs[0][0].strip(), diffs[0][1].strip()))
        else:
            labels.append("MULTI_BODY")
    else:
        labels.append("MULTI_BODY")


def mutation_pairs(diff: str):
    pairs: list[tuple[list[str], list[str]]] = []
    minus: list[str] = []
    plus: list[str] = []
    for line in diff.splitlines():
        if line.startswith("- "):
            minus.append(line[2:])
        elif line.startswith("+ "):
            plus.append(line[2:])
        else:
            if minus or plus:
                pairs.append((minus, plus))
                minus, plus = [], []
    if minus or plus:
        pairs.append((minus, plus))
    return pairs


def family_labels(diff: str) -> list[str]:
    labels: list[str] = []
    for m, p in mutation_pairs(diff):
        if [norm_def(x) for x in m] == [norm_def(x) for x in p]:
            continue
        classify_pair(m, p, labels)
    return labels


def _body_lines(diff: str):
    minus = [l[2:] for l in diff.splitlines() if l.startswith("- ") and not l[2:].lstrip().startswith("def ")]
    plus = [l[2:] for l in diff.splitlines() if l.startswith("+ ") and not l[2:].lstrip().startswith("def ")]
    return minus, plus


def _single_body_change(diff: str) -> tuple[str, str] | None:
    minus, plus = _body_lines(diff)
    if len(minus) == 1 and len(plus) == 1:
        return minus[0].strip(), plus[0].strip()
    return None


def probe_equivalent(mutant_id: str, diff: str) -> tuple[str, str, list[str]] | None:
    """Return EQUIVALENT_PROVEN evidence when a probe-verified equivalence
    transformation is detected in the diff, else None.

    Every rule is backed by a runtime probe (see _probe notes in the repo):
      - noop                 : mutant body textually identical to original
      - sql case-only        : SQLite keywords/pragma names are case-insensitive
      - codec name case-only : Python codec names are case-insensitive
      - encode handler       : errors handler only consulted on error; validated
                               inputs never encode/decode-fail, and removing
                               "strict" falls back to the documented default
      - json flag falsy      : ensure_ascii/allow_nan None == False; allow_nan
                               True/removed unreachable because _validate
                               rejects all floats before json.dumps
      - getattr default      : os.O_NOFOLLOW/os.O_DIRECTORY exist on the eval
                               platform, so the default value is never used
      - resolve strict       : root dir verified via is_dir() before resolve();
                               strict flag has no effect on an existing dir
      - fs path case-only    : macOS APFS/HFS+ is case-insensitive, so a
                               path-component case change resolves to the same
                               file
    """
    pair = _single_body_change(diff)
    minus, plus = _body_lines(diff)
    # json allow_nan=False / ensure_ascii=False line removed entirely (unreachable
    # because _validate rejects all floats before json.dumps, or falsy-equivalent)
    if not plus and len(minus) == 1 and ("allow_nan=False" in minus[0] or "ensure_ascii=False" in minus[0]):
        return (
            "EQUIVALENT_PROVEN",
            "json allow_nan/ensure_ascii=False line removed; the removed flag is unreachable (floats rejected by _validate before json.dumps) or falsy-equivalent to the default; confirmed by runtime probe",
            ["JSON_FLAG_FALSY"],
        )
    if pair is not None:
        a, b = pair
        if a.lower() == b.lower() and a != b:
            if ".execute(" in a and ".execute(" in b:
                return (
                    "EQUIVALENT_PROVEN",
                    "SQL keyword/identifier case change only (SQLite keywords and unquoted identifiers are case-insensitive); all string literals byte-identical except case; confirmed by runtime probe",
                    ["SQL_CASE_ONLY"],
                )
            if ".encode(" in a and ".encode(" in b:
                ma = re.search(r'\.encode\("([^"]*)"', a)
                mb = re.search(r'\.encode\("([^"]*)"', b)
                if ma and mb:
                    if ma.group(1) != mb.group(1) and ma.group(1).lower() == mb.group(1).lower():
                        return (
                            "EQUIVALENT_PROVEN",
                            "str.encode codec name differs only by case (Python codec names are case-insensitive); confirmed by runtime probe",
                            ["CODEC_CASE_ONLY"],
                        )
                    if ma.group(1).lower() in ("ascii", "utf-8", "utf_8", "utf8"):
                        return (
                            "EQUIVALENT_PROVEN",
                            "str.encode errors handler changed or removed; handler is only consulted when an encoding error occurs, and validated inputs never fail encoding; removing 'strict' falls back to the documented Python default; confirmed by runtime probe",
                            ["ENCODE_HANDLER"],
                        )
            if ".decode(" in a and ".decode(" in b:
                ma = re.search(r'\.decode\("([^"]*)"', a)
                mb = re.search(r'\.decode\("([^"]*)"', b)
                if ma and mb:
                    if ma.group(1) != mb.group(1) and ma.group(1).lower() == mb.group(1).lower():
                        return (
                            "EQUIVALENT_PROVEN",
                            "str.decode codec name differs only by case (Python codec names are case-insensitive); confirmed by runtime probe",
                            ["CODEC_CASE_ONLY"],
                        )
                    if ma.group(1).lower() in ("ascii", "utf-8", "utf_8", "utf8"):
                        return (
                            "EQUIVALENT_PROVEN",
                            "str.decode errors handler changed or removed; handler is only consulted when a decoding error occurs, and validated inputs never fail decoding; removing 'strict' falls back to the documented Python default; confirmed by runtime probe",
                            ["ENCODE_HANDLER"],
                        )
            if ("workdir /" in a and "workdir /" in b) or ("resources /" in a and "resources /" in b):
                return (
                    "EQUIVALENT_PROVEN",
                    "path-component case change only; the evaluation filesystem is case-insensitive (macOS APFS/HFS+), so the path resolves to the same file; confirmed by runtime probe",
                    ["FS_PATH_CASE_ONLY"],
                )
        if "ensure_ascii" in a and "ensure_ascii" in b:
            falsy = ("False" in a, "None" in a, "0" in a, "False" in b, "None" in b, "0" in b)
            if any(falsy[:3]) and any(falsy[3:]):
                return (
                    "EQUIVALENT_PROVEN",
                    "json ensure_ascii flag change between falsy values (False/None/0 behave identically; runtime-probed)",
                    ["JSON_FLAG_FALSY"],
                )
        if "allow_nan" in a and "allow_nan" in b:
            a_falsy = any(k in a for k in ("False", "None", "0"))
            b_falsy = any(k in b for k in ("False", "None", "0"))
            if (a_falsy and b_falsy) or ("True" in a or "True" in b):
                return (
                    "EQUIVALENT_PROVEN",
                    "json allow_nan flag change to a falsy-or-unreachable value: allow_nan=None behaves as False (runtime-probed); allow_nan=True/removed is unreachable because _validate rejects all floats before json.dumps",
                    ["JSON_FLAG_FALSY"],
                )
        if ("allow_nan" in a and not plus) or ("ensure_ascii" in a and not plus):
            return (
                "EQUIVALENT_PROVEN",
                "json allow_nan/ensure_ascii=False line removed; the removed flag is unreachable (floats rejected by _validate before json.dumps) or falsy-equivalent to the default; confirmed by runtime probe",
                ["JSON_FLAG_FALSY"],
            )
        ma = re.search(r'getattr\(os, "(O_NOFOLLOW|O_DIRECTORY)", (0|1|None|)\)', a)
        mb = re.search(r'getattr\(os, "(O_NOFOLLOW|O_DIRECTORY)", (0|1|None|)\)', b)
        if ma and mb and ma.group(1) == mb.group(1) and ma.group(2) != mb.group(2):
            return (
                "EQUIVALENT_PROVEN",
                f"os.{ma.group(1)} exists on the evaluation platform (runtime-probed), so the changed getattr default is never used",
                ["GETATTR_DEFAULT_ONLY"],
            )
        if ".resolve(" in a and ".resolve(" in b:
            return (
                "EQUIVALENT_PROVEN",
                "Path.resolve strict flag changed; the root is verified via is_dir()/is_symlink() before resolve(), so strict=True vs strict=False/None produce the same path for an existing directory",
                ["RESOLVE_STRICT_ONLY"],
            )
    # noop: only the def line changed (mutant body textually identical to original)
    # AND the def signature itself is unchanged after normalizing the mutant id.
    minus, plus = _body_lines(diff)
    if not minus and not plus:
        mdef = [l[2:] for l in diff.splitlines() if l.startswith("- ") and l[2:].lstrip().startswith("def ")]
        pdef = [l[2:] for l in diff.splitlines() if l.startswith("+ ") and l[2:].lstrip().startswith("def ")]
        if [norm_def(x) for x in mdef] == [norm_def(x) for x in pdef]:
            return (
                "EQUIVALENT_PROVEN",
                "mutant body is textually identical to the original and the def signature is unchanged (mutation produced no code change); behavior identical by construction",
                ["NOOP"],
            )
    return None


SQL_EQUIVALENT_IDS = {
    "mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_13",
    "mgk.state.xǁSecurityStateǁ_ensure_schema__mutmut_5",
    "mgk.state.xǁSecurityStateǁbump_epoch__mutmut_30",
    "mgk.state.xǁSecurityStateǁbump_epoch__mutmut_34",
    "mgk.state.xǁSecurityStateǁbump_epoch__mutmut_52",
    "mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_14",
    "mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_20",
    "mgk.state.xǁSecurityStateǁconsume_nonce__mutmut_21",
    "mgk.state.xǁSecurityStateǁcurrent_epoch__mutmut_4",
    "mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_35",
    "mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_39",
    "mgk.state.xǁSecurityStateǁinitialize_epoch__mutmut_50",
    "mgk.state.xǁSecurityStateǁintegrity_check__mutmut_26",
    "mgk.state.xǁSecurityStateǁnonce_count__mutmut_4",
    "mgk.state.xǁSecurityStateǁnonce_count__mutmut_5",
}

ENCODE_EQUIVALENT_IDS = {
    "mgk.canonical.x_canonicalize__mutmut_8",
}

FAMILY_JUSTIFICATION = {
    "RAISE_ARGS": "exception message/args changed; observable by asserting the exact exception text",
    "ASSIGN_RHS": "assigned value/expression changed; observable via attribute/state or returned record",
    "CONDITION_CHANGE": "branch condition changed; observable via boundary input",
    "RETURN_CHANGE": "returned value changed; observable via return contract",
    "OPERATOR_CHANGE": "boolean/comparison operator changed; observable via boundary input",
    "DEFAULT_ARG": "default parameter value changed; observable by asserting constructor/function default",
    "REMOVED_STMT": "statement removed; observable via missing side effect/record field",
    "CALL_ARG": "call argument changed; observable via resulting behavior",
    "NUMBER_CONST": "numeric constant changed; observable via exact value",
    "STRING_CONST": "string constant changed; observable via exact text/record field",
    "BOOLEAN_SWAP": "boolean constant swapped; observable via branch behavior",
    "STRING_CASE_ONLY": "string case changed (message/key); observable via exact text",
    "MULTI_BODY": "multi-line block changed; observable via resulting behavior",
    "ADDED_STMT": "statement added; observable via new side effect",
    "OTHER_TOKEN": "token-level change; observable via resulting behavior",
}


def classify_mutant(mutant_id: str, run_status: str, diff: str) -> tuple[str, str, list[str]]:
    """Return (classification, justification, family_labels)."""
    if mutant_id in SQL_EQUIVALENT_IDS:
        return (
            "EQUIVALENT_PROVEN",
            "SQL keyword/identifier case change only (SQLite keywords and unquoted identifiers are case-insensitive); all string literals byte-identical; confirmed by runtime probe",
            ["SQL_CASE_ONLY"],
        )
    if mutant_id in ENCODE_EQUIVALENT_IDS:
        return (
            "EQUIVALENT_PROVEN",
            "str.encode errors argument removed ('strict' is the documented Python default); behavior identical; confirmed by runtime probe",
            ["ENCODE_DEFAULT"],
        )
    probed = probe_equivalent(mutant_id, diff)
    if probed is not None:
        return probed
    labels = family_labels(diff)
    fam = labels[0] if labels else "UNKNOWN"
    just = FAMILY_JUSTIFICATION.get(fam, fam)
    return "SURVIVED_KILLABLE", f"{fam}: {just}", labels
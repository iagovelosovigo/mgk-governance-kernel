import ast
import re
from pathlib import Path

PHASES_PATH = Path("contracts/PHASES.yaml")
ACCEPTANCE_PATH = Path("contracts/FUNCTIONAL_ACCEPTANCE.yaml")
_ID = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _value(raw):
    raw = raw.strip()
    if not raw:
        raise RuntimeError("Empty contract value")
    if raw[0] in "\"'":
        value = ast.literal_eval(raw)
        if not isinstance(value, str):
            raise RuntimeError("Quoted contract value must be a string")
        return value
    if raw == "null":
        return None
    if raw in {"true", "false"}:
        return raw == "true"
    if raw.isdigit():
        return int(raw)
    return raw


def _lines(path):
    text = path.read_text(encoding="utf-8")
    if "\t" in text or "\r" in text:
        raise RuntimeError(f"Unsupported whitespace in {path}")
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def load_phase(phase_id):
    lines = _lines(PHASES_PATH)
    starts = [i for i, line in enumerate(lines) if line.startswith("  - id: ")]
    if not starts:
        raise RuntimeError("No phases found")
    starts.append(len(lines))
    matches = []
    for start, end in zip(starts, starts[1:]):
        current_id = _value(lines[start].split(":", 1)[1])
        if current_id == phase_id:
            matches.append(lines[start:end])
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one phase {phase_id}")

    block = matches[0]
    result = {"id": phase_id}
    index = 1
    while index < len(block):
        line = block[index]
        if not line.startswith("    ") or line.startswith("      ") or ":" not in line:
            raise RuntimeError(f"Malformed phase line: {line!r}")
        key, raw = line.strip().split(":", 1)
        if key in result:
            raise RuntimeError(f"Duplicate phase field: {key}")
        if raw.strip():
            result[key] = _value(raw)
            index += 1
            continue
        values = []
        index += 1
        while index < len(block) and block[index].startswith("      - "):
            values.append(_value(block[index].split("-", 1)[1]))
            index += 1
        if not values or len(values) != len(set(values)):
            raise RuntimeError(f"Invalid list field: {key}")
        result[key] = values

    required = {"id", "name", "next", "max_attempts", "agent", "prompt", "required_gates", "allowed_paths"}
    if set(result) != required:
        raise RuntimeError(f"Unexpected phase schema: {sorted(result)}")
    if not _ID.fullmatch(result["id"]):
        raise RuntimeError("Invalid phase id")
    for gate_id in result["required_gates"]:
        if not _ID.fullmatch(gate_id):
            raise RuntimeError(f"Invalid gate id: {gate_id}")
    return result


def load_acceptance():
    lines = _lines(ACCEPTANCE_PATH)
    result = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith(" ") or ":" not in line:
            raise RuntimeError(f"Malformed acceptance line: {line!r}")
        key, raw = line.split(":", 1)
        if key in result:
            raise RuntimeError(f"Duplicate acceptance field: {key}")
        if raw.strip():
            result[key] = _value(raw)
            index += 1
            continue
        values = []
        index += 1
        while index < len(lines) and lines[index].startswith("  - "):
            values.append(_value(lines[index].split("-", 1)[1]))
            index += 1
        if not values or len(values) != len(set(values)):
            raise RuntimeError(f"Invalid acceptance list: {key}")
        result[key] = values
    if set(result) != {"version", "required_gates", "all_required"}:
        raise RuntimeError("Unexpected acceptance schema")
    if result["all_required"] is not True:
        raise RuntimeError("all_required must be true")
    for gate_id in result["required_gates"]:
        if not _ID.fullmatch(gate_id):
            raise RuntimeError(f"Invalid gate id: {gate_id}")
    return result

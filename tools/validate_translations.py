#!/usr/bin/env python3
"""Validate the starter JSON translation glossary without changing game files."""
import json
import sys
from pathlib import Path

GLOSSARY = Path(__file__).resolve().parents[1] / "translations" / "ui.json"

def main() -> int:
    try:
        data = json.loads(GLOSSARY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read valid UTF-8 JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("ERROR: glossary root must be a JSON object", file=sys.stderr)
        return 1

    errors = []
    for source, target in data.items():
        if not isinstance(source, str) or not source.strip():
            errors.append("source text must be a non-empty string")
        if not isinstance(target, str) or not target.strip():
            errors.append(f"empty/non-string Arabic target for {source!r}")
        if isinstance(source, str) and isinstance(target, str):
            # Warn when common printf placeholders appear to have been dropped.
            import re
            placeholders = re.findall(r"%(?:\d+\$)?[-+#0 ]*(?:\d+)?(?:\.\d+)?[sdif]", source)
            missing = [p for p in placeholders if p not in target]
            if missing:
                errors.append(f"{source!r}: check preserved placeholders {missing}")

    if errors:
        print("\n".join(f"ERROR: {item}" for item in errors), file=sys.stderr)
        return 1

    print(f"OK: {len(data)} glossary entries; UTF-8 JSON is valid.")
    print("Note: this validates only the glossary, not game binary files or in-game RTL.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

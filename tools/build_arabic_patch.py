#!/usr/bin/env python3
"""Build translated copies of WWM localization containers without overwriting inputs.

Usage:
  python tools/build_arabic_patch.py --base /path/translate_words_map_en \
      --diff /path/translate_words_map_en_diff --out-dir build

Requires: Python 3.8+ and zstandard (pip install zstandard).
"""
import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "wwm_locmap.py"
GLOSSARY = ROOT / "translations" / "ui.json"


def run(*args):
    subprocess.run([sys.executable, str(TOOL), *map(str, args)], check=True)


def translate_one(source: Path, destination: Path, glossary: dict, work: Path):
    dump_path = work / (source.name + ".jsonl")
    edited_path = work / (source.name + ".ar.jsonl")
    run("dump", source, dump_path)

    counts = Counter()
    with dump_path.open("r", encoding="utf-8") as fin, edited_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            record = json.loads(line)
            if not record.get("deleted") and "v" in record:
                old = record["v"]
                new = glossary.get(old)
                if new is not None and new != old:
                    record["v"] = new
                    counts[old] += 1
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")

    run("patch", source, edited_path, destination)
    print(f"{source.name}: {sum(counts.values())} slots translated; {len(counts)} distinct source strings matched.")
    for source_text, count in counts.most_common(10):
        print(f"  {count:>6} × {source_text!r} -> {glossary[source_text]!r}")
    return sum(counts.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path, help="original translate_words_map_en")
    parser.add_argument("--diff", required=True, type=Path, help="original translate_words_map_en_diff")
    parser.add_argument("--out-dir", required=True, type=Path, help="new output directory; originals are never changed")
    args = parser.parse_args()

    for path in (args.base, args.diff):
        if not path.is_file():
            parser.error(f"input file does not exist: {path}")
    if args.base.resolve() == args.diff.resolve():
        parser.error("--base and --diff must be different files")

    glossary = json.loads(GLOSSARY.read_text(encoding="utf-8"))
    if not isinstance(glossary, dict) or not glossary:
        parser.error("translation glossary must be a non-empty JSON object")
    for source, target in glossary.items():
        if not isinstance(source, str) or not isinstance(target, str) or not source or not target:
            parser.error("all glossary keys and values must be non-empty strings")

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_dir in (args.base.resolve().parent, args.diff.resolve().parent):
        print("WARNING: output directory is the same as an input directory; output filenames remain separate.")

    work = out_dir / ".work"
    work.mkdir(exist_ok=True)
    base_out = out_dir / "translate_words_map_en"
    diff_out = out_dir / "translate_words_map_en_diff"

    print(f"Loaded {len(glossary)} exact-string translations.")
    total = translate_one(args.base, base_out, glossary, work)
    total += translate_one(args.diff, diff_out, glossary, work)
    print(f"\nDONE: {total} translated slots across both files.")
    print("These are partial test builds, not a complete game translation.")
    print("Test in-game Arabic shaping/RTL before relying on the patch.")
    print(f"Outputs: {base_out} and {diff_out}")


if __name__ == "__main__":
    main()

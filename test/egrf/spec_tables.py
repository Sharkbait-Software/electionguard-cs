#!/usr/bin/env python3
"""Regenerates the schema appendix of docs/spec-compliance/egrf-v2-spec.md (S10b-18).

The tables are generated, never hand-copied: field numbers, types, labels, widths and reserved
numbers come from test/egrf/schema.json (which EgrfSchemaLintTests writes from the compiled
descriptor and checks append-only), and each field's note is the trailing comment of its line in
proto/electionguard/egrf/v2/egrf.proto, joined with the comment-only lines that continue it (aligned
under it, no blank line between). Standard library only. EgrfSchemaLintTests runs --check.

Usage:
    python test/egrf/spec_tables.py           rewrite the appendix between the markers in place
    python test/egrf/spec_tables.py --check   exit 1 if the appendix is not what this script writes
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "test" / "egrf" / "schema.json"
PROTO = ROOT / "proto" / "electionguard" / "egrf" / "v2" / "egrf.proto"
SPEC = ROOT / "docs" / "spec-compliance" / "egrf-v2-spec.md"
BEGIN = "<!-- BEGIN GENERATED: test/egrf/spec_tables.py -->"
END = "<!-- END GENERATED -->"
PACKAGE = ".electionguard.egrf.v2."


def proto_comments():
    """(message, field name) -> the field's trailing comment, continued by the comment-only lines
    that follow it at or beyond its comment's column; the same for enum values. A comment at a
    smaller column (a leading comment of the next member, a oneof group label) or after a blank
    line is not a continuation."""
    comments = {}
    stack = []
    last = None  # (key, column of its trailing "//"): the member whose comment may continue
    for raw in PROTO.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if last is not None and line.startswith("//") and raw.index("//") >= last[1]:
            comments[last[0]] += " " + line[2:].strip()
            continue
        last = None
        opened = re.match(r"^(message|enum|oneof)\s+(\w+)\s*\{", line)
        if opened:
            stack.append((opened.group(1), opened.group(2)))
            continue
        if line.startswith("}"):
            if stack:
                stack.pop()
            continue
        owner = next((name for kind, name in reversed(stack) if kind in ("message", "enum")), None)
        if owner is None:
            continue
        field = re.match(r"^(?:repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+[^;]*;\s*//\s*(.*)$", line) or re.match(r"^(\w+)\s*=\s*\d+\s*;\s*//\s*(.*)$", line)
        if field:
            key = (owner, field.group(1))
            comments[key] = field.group(2).strip()
            last = (key, raw.index("//", raw.index(";")))
    return comments


def cell(text):
    return text.replace("|", "\\|")


def type_of(field):
    kind = field["type"]
    if kind in ("message", "enum"):
        name = field["typeName"]
        return name[len(PACKAGE):] if name.startswith(PACKAGE) else name.lstrip(".")
    return kind


def width_of(field):
    parts = []
    if "width" in field:
        parts.append(f"{field['width']}")
    if "widthMultiple" in field:
        parts.append(f"multiple of {field['widthMultiple']}")
    if field.get("omittable"):
        parts.append("omittable")
    return ", ".join(parts)


def ranges(numbers):
    """schema.json lists every reserved number; consecutive ones are shown as a range."""
    runs = []
    for number in sorted(numbers):
        if runs and number == runs[-1][1] + 1:
            runs[-1][1] = number
        else:
            runs.append([number, number])
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in runs)


def render():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    comments = proto_comments()
    out = [BEGIN, "", f"Package `{schema['package']}`. Generated from `test/egrf/schema.json` and the `.proto`'s field comments; do not edit by hand.", ""]
    out += ["Width (bytes), decode rule D1 (§4.3): a number is the field's exact length; \"multiple of w\" is a positive "
            "whole multiple of w bytes, how many being set by the field's note (the schema does not fix the count); "
            "\"omittable\" means the field may also be left out, as an empty value.", ""]
    out += ["### A.1 Messages", ""]
    for message in schema["messages"]:
        out.append(f"#### `{message['name']}`")
        out.append("")
        if message["reserved"]:
            out.append(f"Reserved: {ranges(message['reserved'])}.")
            out.append("")
        out.append("| # | Field | Type | Label | Width (bytes) | Oneof | Note |")
        out.append("|---|---|---|---|---|---|---|")
        for field in message["fields"]:
            label = "repeated" if field["label"] == "repeated" else ""
            note = comments.get((message["name"], field["name"]), "")
            out.append(f"| {field['number']} | `{field['name']}` | `{type_of(field)}` | {label} | {width_of(field)} | {field.get('oneof', '')} | {cell(note)} |")
        out.append("")
    out += ["### A.2 Enumerations", ""]
    for enum in schema["enums"]:
        out.append(f"#### `{enum['name']}`")
        out.append("")
        out.append("| # | Value | Note |")
        out.append("|---|---|---|")
        for value in enum["values"]:
            out.append(f"| {value['number']} | `{value['name']}` | {cell(comments.get((enum['name'], value['name']), ''))} |")
        out.append("")
    out.append(END)
    return "\n".join(out)


def main():
    text = SPEC.read_text(encoding="utf-8")
    start, end = text.index(BEGIN), text.index(END) + len(END)
    updated = text[:start] + render() + text[end:]
    if "--check" in sys.argv[1:]:
        if updated != text:
            print("egrf-v2-spec.md's schema appendix is out of date: run python test/egrf/spec_tables.py", file=sys.stderr)
            return 1
        print("egrf-v2-spec.md's schema appendix is current.")
        return 0
    SPEC.write_text(updated, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

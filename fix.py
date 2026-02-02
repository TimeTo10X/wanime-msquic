#!/usr/bin/env python3
"""
Removes all QuicTraceEvent(...) calls from .c, .cpp, .h, .hpp files recursively.

Handles:
  - Multi-line calls
  - Nested parentheses  e.g. sizeof(QUIC_CONNECTION)
  - Trailing semicolons
  - String literals containing parens/quotes

Usage:
    python remove_quic_trace_events.py <directory>
    python remove_quic_trace_events.py <directory> --dry-run
"""

import argparse
import os
import sys

EXTENSIONS = {".c", ".cpp", ".h", ".hpp"}
MARKER = "QuicTraceLogStreamInfo"


def strip_trace_events(text: str) -> str:
    """Return text with every QuicTraceEvent(...); removed."""
    result = []
    i = 0
    n = len(text)

    while i < n:
        # ---- look for the marker --------------------------------
        pos = text.find(MARKER, i)
        if pos == -1:
            result.append(text[i:])
            break

        # Walk back over leading whitespace on the same line
        line_start = pos
        while line_start > 0 and text[line_start - 1] in " \t":
            line_start -= 1

        # Keep everything before this call
        result.append(text[i:line_start])

        # ---- skip past the marker name --------------------------
        j = pos + len(MARKER)

        # skip whitespace between name and '('
        while j < n and text[j] in " \t\r\n":
            j += 1

        if j >= n or text[j] != "(":
            # Not actually a function call - keep the text and move on
            result.append(text[line_start:j])
            i = j
            continue

        # ---- walk through balanced parentheses ------------------
        depth = 0
        in_string = False
        in_char = False
        escape_next = False

        while j < n:
            ch = text[j]

            if escape_next:
                escape_next = False
                j += 1
                continue

            if ch == "\\" and (in_string or in_char):
                escape_next = True
                j += 1
                continue

            if not in_string and not in_char:
                if ch == '"':
                    in_string = True
                elif ch == "'":
                    in_char = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        j += 1  # skip the closing ')'
                        break
            elif in_string and ch == '"':
                in_string = False
            elif in_char and ch == "'":
                in_char = False

            j += 1

        # ---- consume optional trailing semicolon + whitespace ---
        while j < n and text[j] in " \t":
            j += 1
        if j < n and text[j] == ";":
            j += 1

        # eat the rest of the now-blank line
        while j < n and text[j] in " \t":
            j += 1
        if j < n and text[j] == "\n":
            j += 1
        elif j < n and text[j] == "\r":
            j += 1
            if j < n and text[j] == "\n":
                j += 1

        i = j

    return "".join(result)


def process_directory(root_dir: str, dry_run: bool = False) -> None:
    files_changed = 0
    total_removals = 0

    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in EXTENSIONS:
                continue

            filepath = os.path.join(dirpath, fname)

            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                original = f.read()

            count = original.count(MARKER)
            if count == 0:
                continue

            modified = strip_trace_events(original)

            if modified != original:
                total_removals += count
                files_changed += 1
                rel = os.path.relpath(filepath, root_dir)
                print(
                    f"  {'[dry-run] ' if dry_run else ''}Removed {count} call(s) in {rel}"
                )

                if not dry_run:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(modified)

    print(
        f"\nDone. {total_removals} QuicTraceEvent call(s) removed across {files_changed} file(s)."
    )
    if dry_run:
        print("(dry-run mode - no files were actually modified)")


def main():
    parser = argparse.ArgumentParser(
        description="Remove all QuicTraceEvent() calls from C/C++ source files."
    )
    parser.add_argument("directory", help="Root directory to process recursively")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed without modifying files",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning '{args.directory}' for QuicTraceEvent calls...\n")
    process_directory(args.directory, dry_run=args.dry_run)


if __name__ == "__main__":
    main()

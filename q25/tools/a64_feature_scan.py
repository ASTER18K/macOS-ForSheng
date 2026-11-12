#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""List instructions that a given CPU model cannot execute.

Every instruction section is disassembled twice with llvm-objdump: once for a
reference CPU that the binary was built for (default: apple-m1) and once for a
target CPU (default: cortex-a55, the smaller core of the Helio G99). A word that
decodes for the reference CPU but not for the target CPU needs a feature the
target lacks. Using a real reference CPU instead of "every feature" keeps data
words that happen to look like SVE or MTE instructions out of the result.

Pointer authentication instructions are reported separately because
pac_neutralize.py rewrites them. System register accesses are not judged here:
the disassembler prints unknown registers by encoding instead of failing.

Usage:
    a64_feature_scan.py [--cpu NAME] [--reference NAME] [--json REPORT] FILE [FILE ...]
    a64_feature_scan.py [--cpu NAME] [--reference NAME] [--json REPORT] @LIST
"""
import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pac_neutralize import classify, find_images, code_ranges  # noqa: E402

OBJDUMP = shutil.which("llvm-objdump") or shutil.which("llvm-objdump-18")
MC = shutil.which("llvm-mc") or shutil.which("llvm-mc-18")
LINE_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$")


def disassemble(obj, option):
    out = subprocess.run([OBJDUMP, "-d", option, obj], capture_output=True, text=True, check=True).stdout
    result = {}
    for line in out.splitlines():
        m = LINE_RE.match(line)
        if m:
            result[int(m.group(1), 16)] = (int(m.group(2), 16), m.group(3).lower(), m.group(4))
    return result


def scan_range(data, offset, size, cpu, reference):
    with tempfile.TemporaryDirectory() as tmp:
        raw = os.path.join(tmp, "code.bin")
        with open(raw, "wb") as handle:
            handle.write(data[offset:offset + size])
        asm = os.path.join(tmp, "wrap.s")
        with open(asm, "w") as handle:
            handle.write('.text\n.incbin "%s"\n' % raw)
        obj = os.path.join(tmp, "wrap.o")
        subprocess.run([MC, "-triple=arm64-apple-darwin", "-filetype=obj", "-o", obj, asm], check=True)
        full = disassemble(obj, "--mattr=+all" if reference == "all" else "--mcpu=" + reference)
        limited = disassemble(obj, "--mcpu=" + cpu)
    return full, limited


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cpu", default="cortex-a55")
    parser.add_argument("--reference", default="apple-m1",
                        help='CPU the binary was built for, or "all" for every feature')
    parser.add_argument("--json")
    parser.add_argument("--examples", type=int, default=3)
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    if not OBJDUMP or not MC:
        raise SystemExit("llvm-objdump and llvm-mc are required")
    paths = []
    for argument in args.files:
        if argument.startswith("@"):
            with open(argument[1:]) as handle:
                paths += [line.rstrip("\n") for line in handle if line.strip()]
        else:
            paths.append(argument)
    totals = collections.Counter()
    pac = collections.Counter()
    per_file = {}
    examples = collections.defaultdict(list)
    words = 0
    undecodable = 0
    for path in paths:
        with open(path, "rb") as handle:
            data = handle.read()
        try:
            images = find_images(data)
        except ValueError:
            continue
        if not images:
            continue
        counts = collections.Counter()
        seen = set()
        for image in images:
            for offset, size, address, name in code_ranges(data, image):
                if (offset, size) in seen:
                    continue
                seen.add((offset, size))
                full, limited = scan_range(data, offset, size, args.cpu, args.reference)
                for at, (w, mnemonic, operands) in full.items():
                    words += 1
                    if mnemonic == "<unknown>":
                        undecodable += 1
                        continue
                    low = limited.get(at)
                    if low is not None and low[1] != "<unknown>":
                        continue
                    kind = classify(w)[0]
                    if kind is not None:
                        pac[mnemonic] += 1
                        continue
                    counts[mnemonic] += 1
                    if len(examples[mnemonic]) < args.examples:
                        examples[mnemonic].append("%s %s %#x: %08x %s %s" % (
                            os.path.basename(path), name, address + at, w, mnemonic, operands))
        if counts:
            per_file[os.path.basename(path)] = dict(counts)
        totals.update(counts)
    print("target cpu: %s, reference cpu: %s" % (args.cpu, args.reference))
    print("words examined: %d, undecodable for the reference cpu: %d" % (words, undecodable))
    print("pointer authentication instructions (handled by pac_neutralize.py): %d" % sum(pac.values()))
    print("other instructions the target cpu lacks: %d in %d files" % (sum(totals.values()), len(per_file)))
    for mnemonic, count in totals.most_common():
        print("  %-12s %8d" % (mnemonic, count))
        for line in examples[mnemonic]:
            print("      " + line)
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(dict(cpu=args.cpu, reference=args.reference, words=words, undecodable=undecodable, pac=dict(pac),
                           other=dict(totals), per_file=per_file,
                           examples={k: v for k, v in examples.items()}), handle, indent=1)
            handle.write("\n")


if __name__ == "__main__":
    main()

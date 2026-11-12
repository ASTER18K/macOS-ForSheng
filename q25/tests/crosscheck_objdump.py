#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare pac_neutralize.classify with llvm-objdump on every word of real binaries.

For each instruction section of each arm64 image the file is disassembled with
llvm-objdump (all features enabled). Every word is then checked both ways:

  * a word classified as a PAC instruction must be shown by the disassembler
    with the same mnemonic, and
  * a word the disassembler shows as a PAC instruction must be classified.

Words the disassembler cannot decode (data inside instruction sections) are
counted, together with how many of them the classifier would have rewritten.

Usage: crosscheck_objdump.py FILE [FILE ...]
       crosscheck_objdump.py @LIST      (one path per line)
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from pac_neutralize import classify, find_images, code_ranges  # noqa: E402

OBJDUMP = shutil.which("llvm-objdump") or shutil.which("llvm-objdump-18")
PAC_MNEMONICS = {
    "retaa", "retab", "eretaa", "eretab", "braa", "brab", "braaz", "brabz", "blraa", "blrab",
    "blraaz", "blrabz", "pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb",
    "paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd",
    "pacga", "ldraa", "ldrab", "paciasp", "pacibsp", "autiasp", "autibsp", "paciaz", "pacibz",
    "autiaz", "autibz", "pacia1716", "pacib1716", "autia1716", "autib1716", "xpaclri",
}
KEY_RE = re.compile(r"AP(IA|IB|DA|DB|GA)Key(Lo|Hi)_EL1", re.I)
LINE_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$")


def wrap_and_check(data, offset, size, address, label, stats, problems):
    """Disassemble one code range and compare word by word.

    llvm-objdump cannot read raw binaries, so a tiny object file is assembled around the bytes.
    """
    mc = shutil.which("llvm-mc") or shutil.which("llvm-mc-18")
    with tempfile.TemporaryDirectory() as tmp:
        raw = os.path.join(tmp, "code.bin")
        with open(raw, "wb") as handle:
            handle.write(data[offset:offset + size])
        asm = os.path.join(tmp, "wrap.s")
        with open(asm, "w") as handle:
            handle.write('.text\n.incbin "%s"\n' % raw)
        obj = os.path.join(tmp, "wrap.o")
        # A Mach-O object carries no ELF mapping symbols, so every word is disassembled as code.
        subprocess.run([mc, "-triple=arm64-apple-darwin", "-filetype=obj", "-o", obj, asm], check=True)
        out = subprocess.run([OBJDUMP, "-d", "--mattr=+all", obj],
                             capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        w = int(m.group(2), 16)
        mnemonic = m.group(3).lower()
        operands = m.group(4)
        where = address + int(m.group(1), 16)
        stats["words"] += 1
        kind, _, name = classify(w)
        if mnemonic == "<unknown>":
            stats["undecodable"] += 1
            if kind not in (None, "hint"):
                stats["undecodable_but_classified"] += 1
                problems.append("%s %#x %#010x undecodable but classified %s" % (label, where, w, name))
            continue
        is_key = mnemonic in ("mrs", "msr") and KEY_RE.search(operands)
        if kind is None:
            if mnemonic in PAC_MNEMONICS or is_key:
                stats["missed"] += 1
                problems.append("%s %#x %#010x %s %s not classified" % (label, where, w, mnemonic, operands))
            continue
        stats["classified"] += 1
        expect = name.split()[0]
        if kind in ("keymsr", "keymrs"):
            ok = bool(is_key) and mnemonic == expect and name.split()[1].lower() in operands.lower()
        else:
            ok = mnemonic == expect
        if not ok:
            stats["mismatch"] += 1
            problems.append("%s %#x %#010x classified %s but disassembles as %s %s" % (
                label, where, w, name, mnemonic, operands))


def main():
    if not OBJDUMP:
        raise SystemExit("llvm-objdump not found")
    total = dict(words=0, classified=0, undecodable=0, undecodable_but_classified=0, missed=0, mismatch=0)
    problems = []
    files = 0
    paths = []
    for argument in sys.argv[1:]:
        if argument.startswith("@"):
            with open(argument[1:]) as handle:
                paths += [line.rstrip("\n") for line in handle if line.strip()]
        else:
            paths.append(argument)
    for path in paths:
        with open(path, "rb") as handle:
            data = handle.read()
        try:
            images = find_images(data)
        except ValueError as error:
            print("skip %s: %s" % (path, error))
            continue
        if not images:
            continue
        files += 1
        seen = set()
        for image in images:
            for offset, size, address, name in code_ranges(data, image):
                if (offset, size) in seen:
                    continue
                seen.add((offset, size))
                label = "%s:%s:%s" % (os.path.basename(path), image.label, name)
                wrap_and_check(data, offset, size, address, label, total, problems)
    print("files: %d" % files)
    for key, value in total.items():
        print("  %-28s %d" % (key, value))
    for line in problems[:40]:
        print("  PROBLEM " + line)
    if len(problems) > 40:
        print("  ... %d more" % (len(problems) - 40))
    sys.exit(1 if total["missed"] or total["mismatch"] else 0)


if __name__ == "__main__":
    main()

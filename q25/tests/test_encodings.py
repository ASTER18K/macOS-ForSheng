#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-check pac_neutralize.classify against the LLVM assembler and disassembler.

Every pointer authentication instruction is assembled with llvm-mc, classified,
and the replacement word is disassembled again and compared with the expected
plain instruction. Requires llvm-mc (LLVM 15 or newer) in PATH.
"""
import itertools
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from pac_neutralize import classify  # noqa: E402

MC = shutil.which("llvm-mc") or shutil.which("llvm-mc-18")
ATTR = "-mattr=+v8.3a,+pauth"


def assemble(lines):
    out = subprocess.run([MC, "-triple=aarch64", ATTR, "--show-encoding"], input="\n".join(lines) + "\n",
                         capture_output=True, text=True, check=True).stdout
    words = []
    for line in out.splitlines():
        m = re.search(r"encoding: \[0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2})\]", line)
        if m:
            words.append(int(m.group(4) + m.group(3) + m.group(2) + m.group(1), 16))
    if len(words) != len(lines):
        raise RuntimeError("assembler produced %d encodings for %d lines" % (len(words), len(lines)))
    return words


def disassemble(words):
    text = "\n".join(" ".join("0x%02x" % ((w >> s) & 0xFF) for s in (0, 8, 16, 24)) for w in words) + "\n"
    out = subprocess.run([MC, "-triple=aarch64", "-mattr=+v8a", "--disassemble"], input=text,
                         capture_output=True, text=True).stdout
    result = [re.sub(r"\s+", " ", line.strip()) for line in out.splitlines()
              if line.strip() and not line.strip().startswith(".")]
    if len(result) != len(words):
        raise RuntimeError("disassembler produced %d lines for %d words" % (len(result), len(words)))
    return result


def norm(text):
    # The disassembler appends "// =0x0" style comments to some aliases.
    return re.sub(r"\s+", " ", text.split("//")[0].strip())


def main():
    if not MC:
        raise SystemExit("llvm-mc not found")
    regs = ["x0", "x1", "x8", "x16", "x17", "x29", "x30"]
    cases = []  # (source, expected kind, expected replacement text or None)
    for name in ("retaa", "retab"):
        cases.append((name, "ret", "ret"))
    for name in ("eretaa", "eretab"):
        cases.append((name, "eret", "eret"))
    for name, plain in (("braa", "br"), ("brab", "br"), ("blraa", "blr"), ("blrab", "blr")):
        for rn, rm in itertools.product(regs, ["x1", "x9", "x17", "sp"]):
            cases.append(("%s %s, %s" % (name, rn, rm), plain, "%s %s" % (plain, rn)))
    for name, plain in (("braaz", "br"), ("brabz", "br"), ("blraaz", "blr"), ("blrabz", "blr")):
        for rn in regs:
            cases.append(("%s %s" % (name, rn), plain, "%s %s" % (plain, rn)))
    for name in ("pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"):
        for rd, rn in itertools.product(regs, ["x2", "x17", "sp"]):
            cases.append(("%s %s, %s" % (name, rd, rn), "strip", "nop"))
    for name in ("paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd"):
        for rd in regs:
            cases.append(("%s %s" % (name, rd), "strip", "nop"))
    for rd, rn, rm in itertools.product(["x0", "x3", "x17"], ["x1", "x16", "x30"], ["x2", "x9", "sp"]):
        cases.append(("pacga %s, %s, %s" % (rd, rn, rm), "pacga", "and %s, %s, #0xffffffff00000000" % (rd, rn)))
    cases.append(("pacga xzr, x1, x2", "pacga", "nop"))
    for name in ("ldraa", "ldrab"):
        for rt, rn in itertools.product(["x0", "x8", "x16"], ["x1", "x16", "sp"]):
            for offset in (0, 8, 16, 248, 256, 2040, 4088):
                cases.append(("%s %s, [%s, #%d]" % (name, rt, rn, offset), "ldra",
                              "ldr %s, [%s%s]" % (rt, rn, ", #%d" % offset if offset else "")))
            for offset in (-8, -128, -256):
                cases.append(("%s %s, [%s, #%d]" % (name, rt, rn, offset), "ldra",
                              "ldur %s, [%s, #%d]" % (rt, rn, offset)))
            for offset in (-264, -2048, -4096):
                cases.append(("%s %s, [%s, #%d]" % (name, rt, rn, offset), "ldra-unconvertible", None))
            if rt != rn:
                for offset in (0, 8, 248, -8, -256):
                    cases.append(("%s %s, [%s, #%d]!" % (name, rt, rn, offset), "ldra",
                                  "ldr %s, [%s, #%d]!" % (rt, rn, offset)))
                for offset in (256, 4088, -264, -4096):
                    cases.append(("%s %s, [%s, #%d]!" % (name, rt, rn, offset), "ldra-unconvertible", None))
    keys = ["APIAKeyLo_EL1", "APIAKeyHi_EL1", "APIBKeyLo_EL1", "APIBKeyHi_EL1", "APDAKeyLo_EL1",
            "APDAKeyHi_EL1", "APDBKeyLo_EL1", "APDBKeyHi_EL1", "APGAKeyLo_EL1", "APGAKeyHi_EL1"]
    for key in keys:
        for reg in ("x0", "x4", "x17"):
            cases.append(("msr %s, %s" % (key, reg), "keymsr", "nop"))
            cases.append(("mrs %s, %s" % (reg, key), "keymrs", "mov %s, #0" % reg))
    for name in ("paciasp", "pacibsp", "autiasp", "autibsp", "paciaz", "pacibz", "autiaz", "autibz",
                 "pacia1716", "pacib1716", "autia1716", "autib1716", "xpaclri"):
        cases.append((name, "hint", None))
    # Instructions that must never be classified.
    negatives = ["ret", "ret x1", "eret", "br x16", "blr x8", "nop", "bti c", "ldr x0, [x1, #8]",
                 "ldr x0, [x1, #8]!", "ldur x0, [x1, #-8]", "ldr x0, [x1, x2]", "ldr x0, [x1, x2, lsl #3]",
                 "mrs x0, SCTLR_EL1", "msr SCTLR_EL1, x0", "msr TTBR0_EL1, x1", "mrs x3, TCR_EL1",
                 "mrs x0, ID_AA64ISAR1_EL1", "clz x0, x1", "rbit x0, x1", "rev x0, x1", "cls x2, x3",
                 "lslv x0, x1, x2", "udiv x0, x1, x2", "crc32x w0, w1, x2", "and x0, x1, #0xffffffff00000000",
                 "hint #34", "isb", "wfi", "svc #0x80", "brk #0xc471", "ldaxr x0, [x1]", "casal x0, x1, [x2]",
                 "swpal x0, x1, [x2]", "ldaddal x0, x1, [x2]", "prfm pldl1keep, [x0, #8]", "str x0, [x1, #8]!",
                 "ldrsw x0, [x1], #4", "mov x0, #0", "movk x17, #0xd0e1, lsl #48", "ldapr x0, [x1]"]
    sources = [c[0] for c in cases]
    words = assemble(sources)
    failures = 0
    replacements = []
    for (source, kind, expected), w in zip(cases, words):
        got_kind, new, mnemonic = classify(w)
        if got_kind != kind or mnemonic.split()[0] != source.split()[0]:
            print("FAIL classify %-34s %#010x -> %r %r" % (source, w, got_kind, mnemonic))
            failures += 1
            continue
        if expected is None:
            if new is not None:
                print("FAIL %-34s unexpected replacement %#010x" % (source, new))
                failures += 1
        else:
            if new is None:
                print("FAIL %-34s has no replacement" % source)
                failures += 1
            else:
                replacements.append((source, expected, new))
    texts = disassemble([r[2] for r in replacements])
    for (source, expected, new), text in zip(replacements, texts):
        if norm(text) != norm(expected):
            print("FAIL replace  %-34s -> %#010x = %r, expected %r" % (source, new, text, expected))
            failures += 1
    negative_words = assemble(negatives)
    for source, w in zip(negatives, negative_words):
        if classify(w)[0] is not None:
            print("FAIL negative %-34s %#010x classified as %r" % (source, w, classify(w)))
            failures += 1
    print("cases: %d positive (%d with replacement), %d negative, failures: %d" % (
        len(cases), len(replacements), len(negatives), failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

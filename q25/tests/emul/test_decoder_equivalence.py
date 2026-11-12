#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that the kernel decoder (a64e.h) and tools/pac_neutralize.py decode identically.

The C decoder is compiled for the host, fed several million instruction words
(complete enumerations of the encoding spaces that hold PAC instructions, random
words, and optionally every word of real binaries) and compared field by field
with the Python classifier.

Usage: test_decoder_equivalence.py [MACH-O FILE ...]
"""
import array
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
from pac_neutralize import classify, find_images, code_ranges  # noqa: E402

KINDS = {None: 0, "hint": 1, "ret": 2, "eret": 3, "br": 4, "blr": 5, "strip": 6, "pacga": 7,
         "ldra": 8, "ldra-unconvertible": 8, "keymsr": 9, "keymrs": 10}


def words():
    out = array.array("I")
    # LDRAA / LDRAB: every combination of the 22 free bits
    for free in range(1 << 22):
        w = 0xF8200400 | ((free & 0x3) << 22)            # M, S
        w |= ((free >> 2) & 0x1FF) << 12                 # imm9
        w |= ((free >> 11) & 1) << 11                    # W
        w |= ((free >> 12) & 0x3FF)                      # Rn, Rt
        out.append(w)
    # Data processing (1 source) with opcode2 = 00001
    out.extend(0xDAC10000 | low for low in range(1 << 16))
    # Data processing (2 source), 64-bit: includes PACGA
    out.extend(0x9AC00000 | low for low in range(1 << 21))
    # Unconditional branch (register): all option bits, every Rn, selected Rm
    for high in range(1 << 15):
        base = 0xD6000000 | (high << 10)
        for rn in range(32):
            for rm in (0, 1, 17, 30, 31):
                out.append(base | (rn << 5) | rm)
    # System instructions and registers
    out.extend(0xD5000000 | low for low in range(1 << 22))
    rng = random.Random(20261112)
    out.extend(rng.getrandbits(32) for _ in range(4_000_000))
    return out


def main():
    data = words()
    for path in sys.argv[1:]:
        with open(path, "rb") as handle:
            blob = handle.read()
        for image in find_images(blob):
            for offset, size, _, _ in code_ranges(blob, image):
                data.frombytes(blob[offset:offset + (size & ~3)])
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "decode_dump")
        subprocess.run(["clang", "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-o", binary,
                        os.path.join(HERE, "decode_dump.c")], check=True)
        result = subprocess.run([binary], input=data.tobytes(), capture_output=True, check=True).stdout
    lines = result.split(b"\n")
    if len(lines) - 1 != len(data):
        raise SystemExit("C tool returned %d lines for %d words" % (len(lines) - 1, len(data)))
    mismatches = 0
    pac = 0
    for w, line in zip(data, lines):
        kind_c, replacement_c, offset_c, rn_c, rt_c, wb_c = line.split()
        kind_c = int(kind_c)
        replacement_c = int(replacement_c, 16)
        top = w >> 24
        if top in (0xD5, 0xD6, 0xD7, 0xDA, 0x9A, 0xF8):
            kind, replacement, _ = classify(w)
        else:
            kind, replacement = None, None
        expected_kind = KINDS[kind]
        expected_replacement = replacement or 0
        ok = kind_c == expected_kind and replacement_c == expected_replacement
        if ok and kind in ("ldra", "ldra-unconvertible"):
            sign = (w >> 22) & 1
            offset = (sign << 9) | ((w >> 12) & 0x1FF)
            if offset & 0x200:
                offset -= 0x400
            ok = (int(offset_c) == offset * 8 and int(rn_c) == ((w >> 5) & 31)
                  and int(rt_c) == (w & 31) and int(wb_c) == ((w >> 11) & 1))
        if kind_c:
            pac += 1
        if not ok:
            mismatches += 1
            if mismatches <= 10:
                print("MISMATCH %#010x: C kind=%d replacement=%#010x, Python kind=%r replacement=%r" % (
                    w, kind_c, replacement_c, kind, replacement))
    print("words compared: %d, classified as PAC by the C decoder: %d, mismatches: %d" % (
        len(data), pac, mismatches))
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()

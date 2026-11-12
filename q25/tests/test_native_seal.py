#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test the rewrite of a kernel that carries the native provider integrity field.

scripts/seal_macos26_crypto.py stores HMAC-SHA256 (32 zero key bytes) over the
__cc26_text section in the single 32-byte __fips_hmacs section and records the
value in build.json. Rewriting instructions inside __cc26_text invalidates that
value, so neutralize_build.py has to recompute it and keep the record truthful.

A small ARM64E executable with the same section layout is built here, sealed the
same way and passed through neutralize_build.py. No Apple input is needed.

Checks: the field is recomputed over the rewritten section, build.json follows,
a stale field is refused, and an image with two integrity fields is refused.
"""
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools")
sys.path.insert(0, TOOLS)
import pac_neutralize  # noqa: E402

BASE = 0xFFFFFE0007004000
PAGE = 0x4000
CODE = 0x80000400       # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
NOP = 0xD503201F
RET = 0xD65F03C0
# pacibsp, mov x0 #0, blraaz x8, autda x0 x1, xpaci x3, pacga x0 x1 x2, retab
GENERAL = [0xD503237F, 0xD2800000, 0xD63F091F, 0xDAC11820, 0xDAC143E3, 0x9AC23020, 0xD65F0FFF, NOP]
# pacibsp, braa x16 x17, ldraa x0 [x1], mrs x0 APIAKeyLo_EL1, msr APIBKeyHi_EL1 x1, nop, retaa, ret
PROVIDER = [0xD503237F, 0xD71F0A11, 0xF8200420, 0xD5382100, 0xD5182161, NOP, 0xD65F0BFF, RET]
failures = 0


def check(condition, label):
    global failures
    print("[%s] %s" % ("OK" if condition else "NG", label))
    if not condition:
        failures += 1


def segment_command(name, vmaddr, size, fileoff, prot, sections=()):
    return struct.pack("<II16sQQQQiiII", 0x19, 72 + 80 * len(sections), name.encode(), vmaddr, size,
                       fileoff, size, prot, prot, len(sections), 0) + b"".join(sections)


def section_command(name, segment, addr, size, offset, flags=0):
    return struct.pack("<16s16sQQIIIIIIII", name.encode(), segment.encode(), addr, size, offset,
                       2, 0, 0, flags, 0, 0, 0)


def build_kernel(integrity_fields=1):
    """Return (bytes, provider text offset, provider text size, integrity offsets)."""
    general = struct.pack("<%dI" % len(GENERAL), *GENERAL)
    provider = struct.pack("<%dI" % len(PROVIDER), *PROVIDER)
    exec_off, data_off = PAGE, 2 * PAGE
    exec_va, data_va = BASE + exec_off, BASE + data_off
    provider_off = exec_off + len(general)
    data_sections = [section_command("__fips_hmacs", "__DATA_CONST", data_va + 64 * i, 32, data_off + 64 * i)
                     for i in range(integrity_fields)]
    commands = [
        segment_command("__TEXT", BASE, PAGE, 0, 1),
        segment_command("__TEXT_EXEC", exec_va, PAGE, exec_off, 5, [
            section_command("__text", "__TEXT_EXEC", exec_va, len(general), exec_off, CODE),
            section_command("__cc26_text", "__TEXT_EXEC", exec_va + len(general), len(provider), provider_off, CODE),
        ]),
        segment_command("__DATA_CONST", data_va, PAGE, data_off, 3, data_sections),
    ]
    body = b"".join(commands)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0xC0000002, 2, len(commands), len(body), 0x200001, 0)
    out = bytearray(3 * PAGE)
    out[:len(header) + len(body)] = header + body
    out[exec_off:exec_off + len(general)] = general
    out[provider_off:provider_off + len(provider)] = provider
    out[exec_off + len(general) + len(provider):exec_off + PAGE] = struct.pack("<I", NOP) * (
        (PAGE - len(general) - len(provider)) // 4)
    return out, provider_off, len(provider), [data_off + 64 * i for i in range(integrity_fields)]


def seal(data, text_off, text_size, field_off):
    mac = hmac.digest(bytes(32), bytes(data[text_off:text_off + text_size]), "sha256")
    data[field_off:field_off + 32] = mac
    return mac


def write_build(directory, data, mac):
    os.makedirs(directory)
    with open(os.path.join(directory, "kernel.development.sheng"), "wb") as stream:
        stream.write(data)
    digest = hashlib.sha256(data).hexdigest()
    with open(os.path.join(directory, "build.json"), "w") as stream:
        json.dump(dict(architecture="arm64e", machine="SHENG", executable_kernel_sha256=digest,
                       corecrypto_integrity=dict(kernel_sha256=digest, hmac_sha256=mac.hex(),
                                                 runtime_post_passed=False)), stream)
    with open(os.path.join(directory, "kernel.development.sheng.map"), "w") as stream:
        stream.write("map\n")
    return digest


def neutralize(source, target):
    return subprocess.run([sys.executable, "-I", os.path.join(TOOLS, "neutralize_build.py"), source, target],
                          capture_output=True, text=True)


def main():
    for word in GENERAL + PROVIDER:
        kind = pac_neutralize.classify(word)[0]
        expected_plain = word in (NOP, RET, 0xD2800000)
        if (kind is None) != expected_plain:
            raise SystemExit("test fixture word %#010x is not what the test assumes" % word)
    with tempfile.TemporaryDirectory() as tmp:
        data, text_off, text_size, fields = build_kernel()
        mac = seal(data, text_off, text_size, fields[0])
        source = os.path.join(tmp, "build")
        digest = write_build(source, data, mac)
        target = os.path.join(tmp, "neutral")
        run = neutralize(source, target)
        check(run.returncode == 0, "neutralize_build.py accepts the sealed kernel: %s" % run.stderr.strip()[:200])
        if run.returncode == 0:
            out = open(os.path.join(target, "kernel.development.sheng"), "rb").read()
            build = json.load(open(os.path.join(target, "build.json")))
            fresh = hmac.digest(bytes(32), out[text_off:text_off + text_size], "sha256")
            check(out[text_off:text_off + text_size] != bytes(data[text_off:text_off + text_size]),
                  "instructions inside the provider section were rewritten")
            check(out[fields[0]:fields[0] + 32] == fresh and fresh != mac,
                  "the integrity field holds the HMAC of the rewritten provider section")
            seal_record = build["corecrypto_integrity"]
            check(seal_record["hmac_sha256"] == fresh.hex() and seal_record["pac_neutral_source_hmac_sha256"] == mac.hex(),
                  "build.json records the new value and keeps the original one")
            new_digest = hashlib.sha256(out).hexdigest()
            check(build["executable_kernel_sha256"] == new_digest == seal_record["kernel_sha256"]
                  and build["pac_neutral"]["source_kernel_sha256"] == digest, "recorded hashes describe the rewritten image")
            check(out[28:32] == b"NPAC", "loader marker is present")
            again = pac_neutralize.process(bytearray(out), rewrite=False)
            check(set(again["summary"]) == {"hint"} and again["hmac"][0]["stored_matches_original_text"],
                  "only HINT-space forms remain and the field verifies: %r" % again["summary"])
            words = struct.unpack_from("<%dI" % (len(GENERAL) + len(PROVIDER)), out, PAGE)
            expected = (0xD503237F, 0xD2800000, 0xD63F0100, NOP, NOP, 0x92607C20, RET, NOP,
                        0xD503237F, 0xD61F0200, 0xF9400020, 0xD2800000, NOP, NOP, RET, RET)
            check(words == expected, "every instruction became its identity equivalent")

        stale, text_off, text_size, fields = build_kernel()
        mac = seal(stale, text_off, text_size, fields[0])
        stale[fields[0]] ^= 0xFF
        source = os.path.join(tmp, "stale")
        write_build(source, stale, mac)
        run = neutralize(source, os.path.join(tmp, "stale-out"))
        check(run.returncode != 0 and "integrity field" in run.stderr and not os.path.exists(os.path.join(tmp, "stale-out")),
              "a kernel whose field does not match its text is refused: %s" % run.stderr.strip()[:90])

        double, text_off, text_size, fields = build_kernel(integrity_fields=2)
        mac = seal(double, text_off, text_size, fields[0])
        seal(double, text_off, text_size, fields[1])
        source = os.path.join(tmp, "double")
        write_build(source, double, mac)
        run = neutralize(source, os.path.join(tmp, "double-out"))
        check(run.returncode != 0 and "integrity field" in run.stderr and not os.path.exists(os.path.join(tmp, "double-out")),
              "a kernel with two integrity fields is refused: %s" % run.stderr.strip()[:90])
    print("failures: %d" % failures)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test embedded-image handling with real Apple kernel extensions.

A container is assembled the way scripts/emit_macos26_security.py lays out its
candidate: an outer MH_EXECUTE whose __PRELINK_TEXT segment holds the relocated
Mach-O headers of the components plus a __macho_list section with their
addresses, and whose __PLK_TEXT_EXEC segment holds their code in one unflagged
section. The components are the arm64e slices of corecrypto and apfs from a
Kernel Debug Kit.

Checks: the components are found through __macho_list, every PAC instruction in
them is rewritten, corecrypto's integrity field is recomputed, a container
without __macho_list trips the safety net, and neutralize_build.py produces a
consistent build directory.

Usage: test_container.py KDK_EXTENSIONS_DIR
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
failures = 0


def check(condition, label):
    global failures
    print("[%s] %s" % ("OK" if condition else "NG", label))
    if not condition:
        failures += 1


def arm64e_slice(path):
    data = open(path, "rb").read()
    magic, = struct.unpack_from(">I", data, 0)
    if magic == 0xCAFEBABE:
        for i in range(struct.unpack_from(">I", data, 4)[0]):
            cputype, _, off, size, _ = struct.unpack_from(">iiIII", data, 8 + 20 * i)
            if cputype == 0x0100000C:
                return data[off:off + size]
        raise SystemExit("no arm64 slice in " + path)
    return data


def segments_of(blob):
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    pos = 32
    out = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", blob, pos)
        if cmd == 0x19:
            name, vmaddr, vmsize, fileoff, filesize, _, _, nsects, _ = struct.unpack_from("<16sQQQQiiII", blob, pos + 8)
            out.append(dict(pos=pos, name=name.rstrip(b"\0").decode(), vmaddr=vmaddr, vmsize=vmsize,
                            fileoff=fileoff, filesize=filesize, nsects=nsects))
        pos += size
    return out


def align(value, boundary=PAGE):
    return (value + boundary - 1) & -boundary


def segment_command(name, vmaddr, size, fileoff, prot, sections=()):
    return struct.pack("<II16sQQQQiiII", 0x19, 72 + 80 * len(sections), name.encode(), vmaddr, size,
                       fileoff, size, prot, prot, len(sections), 0) + b"".join(sections)


def section_command(name, segment, addr, size, offset, flags=0):
    return struct.pack("<16s16sQQIIIIIIII", name.encode(), segment.encode(), addr, size, offset,
                       3, 0, 0, flags, 0, 0, 0)


def build_container(components, with_list=True):
    """Return the container bytes for a list of thin arm64e kext images."""
    header_space = PAGE
    text_blob = bytearray()
    exec_blob = bytearray()
    placements = []
    for blob in components:
        segs = {s["name"]: s for s in segments_of(blob)}
        text, code = segs["__TEXT"], segs["__TEXT_EXEC"]
        text_at = align(len(text_blob))
        text_blob.extend(bytes(text_at - len(text_blob)))
        text_blob.extend(blob[text["fileoff"]:text["fileoff"] + text["filesize"]])
        code_at = align(len(exec_blob))
        exec_blob.extend(bytes(code_at - len(exec_blob)))
        exec_blob.extend(blob[code["fileoff"]:code["fileoff"] + code["filesize"]])
        placements.append((blob, text, code, text_at, code_at))
    list_at = align(len(text_blob), 8)
    text_blob.extend(bytes(list_at - len(text_blob)))
    text_va = BASE + header_space
    text_blob.extend(b"".join(struct.pack("<Q", text_va + p[3]) for p in placements))
    text_blob.extend(bytes(align(len(text_blob)) - len(text_blob)))
    exec_va = text_va + len(text_blob)
    exec_blob.extend(bytes(align(len(exec_blob)) - len(exec_blob)))
    text_off = header_space
    exec_off = text_off + len(text_blob)
    # Relocate the embedded headers: segment and section addresses become outer addresses.
    for blob, text, code, text_at, code_at in placements:
        deltas = {"__TEXT": text_va + text_at - text["vmaddr"], "__TEXT_EXEC": exec_va + code_at - code["vmaddr"]}
        file_bases = {"__TEXT": text_off + text_at, "__TEXT_EXEC": exec_off + code_at}
        for seg in segments_of(blob):
            if seg["name"] not in deltas:
                continue
            at = text_at + seg["pos"]
            delta = deltas[seg["name"]]
            struct.pack_into("<QQQ", text_blob, at + 24, seg["vmaddr"] + delta, seg["vmsize"], file_bases[seg["name"]])
            for i in range(seg["nsects"]):
                sec = at + 72 + 80 * i
                addr, = struct.unpack_from("<Q", text_blob, sec + 32)
                struct.pack_into("<Q", text_blob, sec + 32, addr + delta)
                old_off, = struct.unpack_from("<I", text_blob, sec + 48)
                if old_off:
                    struct.pack_into("<I", text_blob, sec + 48, old_off - seg["fileoff"] + file_bases[seg["name"]])
    sections = [section_command("__text", "__PRELINK_TEXT", text_va, list_at, text_off)]
    if with_list:
        sections.append(section_command("__macho_list", "__PRELINK_TEXT", text_va + list_at,
                                        8 * len(placements), text_off + list_at))
    commands = [
        segment_command("__TEXT", BASE, header_space, 0, 1),
        segment_command("__PRELINK_TEXT", text_va, len(text_blob), text_off, 1, sections),
        segment_command("__PLK_TEXT_EXEC", exec_va, len(exec_blob), exec_off, 5,
                        [section_command("__data", "__PLK_TEXT_EXEC", exec_va, len(exec_blob), exec_off)]),
    ]
    body = b"".join(commands)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0xC0000002, 2, len(commands), len(body), 0x200001, 0)
    out = bytearray(header + body)
    out.extend(bytes(header_space - len(out)))
    out.extend(text_blob)
    out.extend(exec_blob)
    return bytes(out), placements, (text_off, exec_off)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    ext = sys.argv[1]
    names = ["corecrypto", "apfs"]
    components = [arm64e_slice(os.path.join(ext, n + ".kext", "Contents", "MacOS", n)) for n in names]
    standalone = [pac_neutralize.process(bytearray(c), rewrite=False) for c in components]
    expected = {}
    for report in standalone:
        for key, value in report["summary"].items():
            expected[key] = expected.get(key, 0) + value

    container, placements, _ = build_container(components)
    data = bytearray(container)
    report = pac_neutralize.process(data, rewrite=True)
    check(len(report["image_labels"]) == 3, "outer image and both embedded components are found")
    check(report["summary"] == expected, "instruction counts equal the standalone components: %r" % report["summary"])
    check(report["uncovered_executable_returns"] == 0, "no authenticated return outside the located code")
    check(len(report["hmac"]) == 1 and report["hmac"][0]["stored_matches_original_text"]
          and report["hmac"][0]["resealed"], "corecrypto integrity field matched and was recomputed")
    entry = report["hmac"][0]
    fresh = hmac.digest(bytes(32), bytes(data[entry["text_file_offset"]:entry["text_file_offset"] + entry["text_bytes"]]), "sha256")
    check(bytes(data[entry["hmac_file_offset"]:entry["hmac_file_offset"] + 32]) == fresh,
          "stored integrity value equals HMAC of the rewritten text")
    again = pac_neutralize.process(bytearray(data), rewrite=False)
    check(set(again["summary"]) == {"hint"}, "only HINT-space forms remain: %r" % again["summary"])
    changed = sum(v for k, v in expected.items() if k != "hint")
    check(report["changed_words"] == changed, "changed words (%d) equal the non-HINT instruction count" % changed)

    no_list, _, _ = build_container(components, with_list=False)
    blind = pac_neutralize.process(bytearray(no_list), rewrite=False)
    check(blind["uncovered_executable_returns"] > 0 and set(blind["summary"]) == set(),
          "without __macho_list the safety net reports %d uncovered returns" % blind["uncovered_executable_returns"])

    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "candidate")
        os.makedirs(os.path.join(source, "kernel.development.sheng.dSYM"))
        with open(os.path.join(source, "kernel.development.sheng"), "wb") as stream:
            stream.write(container)
        digest = hashlib.sha256(container).hexdigest()
        json.dump(dict(architecture="arm64e", executable_kernel_sha256=digest, machine="SHENG"),
                  open(os.path.join(source, "build.json"), "w"))
        json.dump(dict(candidate_sha256=digest, modules={n: {} for n in names}),
                  open(os.path.join(source, "security-relink.json"), "w"))
        open(os.path.join(source, "kernel.development.sheng.map"), "w").write("map\n")
        target = os.path.join(tmp, "neutral")
        run = subprocess.run([sys.executable, "-I", os.path.join(TOOLS, "neutralize_build.py"), source, target],
                             capture_output=True, text=True)
        check(run.returncode == 0, "neutralize_build.py succeeds: %s" % run.stderr.strip()[:200])
        if run.returncode == 0:
            out = open(os.path.join(target, "kernel.development.sheng"), "rb").read()
            build = json.load(open(os.path.join(target, "build.json")))
            relink = json.load(open(os.path.join(target, "security-relink.json")))
            new_digest = hashlib.sha256(out).hexdigest()
            check(build["executable_kernel_sha256"] == new_digest == relink["candidate_sha256"],
                  "recorded hashes describe the rewritten image")
            check(out[28:32] == b"NPAC", "loader marker is present")
            check(build["pac_neutral"]["source_kernel_sha256"] == digest, "source hash is recorded")
            check(os.path.isdir(os.path.join(target, "kernel.development.sheng.dSYM"))
                  and os.path.isfile(os.path.join(target, "kernel.development.sheng.map")), "dSYM and map are carried over")
            expect = bytearray(data)
            struct.pack_into("<I", expect, 28, pac_neutralize.MARK)
            check(bytes(expect) == out, "output equals the direct rewrite plus the marker")
            second = subprocess.run([sys.executable, "-I", os.path.join(TOOLS, "neutralize_build.py"), target,
                                     os.path.join(tmp, "twice")], capture_output=True, text=True)
            check(second.returncode != 0 and "already PAC-neutral" in second.stderr, "a second pass is refused")
        # A candidate whose component list cannot be found must be refused.
        broken = os.path.join(tmp, "broken")
        os.makedirs(broken)
        open(os.path.join(broken, "kernel.development.sheng"), "wb").write(no_list)
        digest = hashlib.sha256(no_list).hexdigest()
        json.dump(dict(architecture="arm64e", executable_kernel_sha256=digest), open(os.path.join(broken, "build.json"), "w"))
        json.dump(dict(candidate_sha256=digest, modules={n: {} for n in names}),
                  open(os.path.join(broken, "security-relink.json"), "w"))
        refused = subprocess.run([sys.executable, "-I", os.path.join(TOOLS, "neutralize_build.py"), broken,
                                  os.path.join(tmp, "broken-out")], capture_output=True, text=True)
        check(refused.returncode != 0 and not os.path.exists(os.path.join(tmp, "broken-out")),
              "a candidate with unlocated code is refused: %s" % refused.stderr.strip()[:120])
    print("failures: %d" % failures)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Make arm64e kernel images runnable on CPUs without pointer authentication.

On a CPU without FEAT_PAuth (Cortex-A76, Cortex-A55, ...) only the HINT-space
PAC instructions (PACIASP, AUTIBSP, XPACLRI, ...) execute as NOPs. Every other
PAC instruction is UNDEFINED and traps. This tool rewrites those instructions
one-for-one into equivalents that treat pointer authentication as the identity
function:

    RETAA / RETAB                     -> RET
    ERETAA / ERETAB                   -> ERET
    BRAA / BRAB / BRAAZ / BRABZ       -> BR  Xn
    BLRAA / BLRAB / BLRAAZ / BLRABZ   -> BLR Xn
    PACxx / AUTxx / XPACI / XPACD     -> NOP          (register forms)
    PACGA Xd, Xn, Xm                  -> AND Xd, Xn, #0xffffffff00000000
    LDRAA / LDRAB                     -> LDR / LDUR / pre-indexed LDR when the
                                         offset can be encoded, otherwise the
                                         site is reported and left untouched
    MSR APxxKey{Lo,Hi}_EL1, Xt        -> NOP
    MRS Xt, APxxKey{Lo,Hi}_EL1        -> MOV Xt, #0

Only bytes inside sections marked as instructions are examined. Supported
containers: thin or fat Mach-O (MH_EXECUTE, MH_KEXT_BUNDLE, MH_OBJECT),
MH_FILESET kernel collections, kernel images that list embedded Mach-O headers
in __PRELINK_TEXT,__macho_list, and (for tests only) ELF64 executables.

corecrypto integrity fields (__fips_hmacs: HMAC-SHA256 with a 32-byte zero key
over the provider text) are recomputed after rewriting when, and only when, the
stored value matched the original bytes.

Usage:
    pac_neutralize.py scan    INPUT [--json REPORT]
    pac_neutralize.py rewrite INPUT OUTPUT [--json REPORT] [--mark] [--no-reseal]
"""
import argparse
import hashlib
import hmac
import json
import struct
import sys

NOP = 0xD503201F
RET = 0xD65F03C0
ERET = 0xD69F03E0
MARK = 0x4341504E  # bytes "NPAC" in mach_header_64.reserved

CPU_TYPE_ARM64 = 0x0100000C
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SEGMENT_64 = 0x19
LC_DATA_IN_CODE = 0x29
LC_FILESET_ENTRY = 0x80000035
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
ZEROFILL_TYPES = (0x1, 0xC, 0x12)

HINT_NAMES = {
    7: "xpaclri", 8: "pacia1716", 10: "pacib1716", 12: "autia1716", 14: "autib1716",
    24: "paciaz", 25: "paciasp", 26: "pacibz", 27: "pacibsp",
    28: "autiaz", 29: "autiasp", 30: "autibz", 31: "autibsp",
}
DP1_NAMES = ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb",
             "paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb",
             "xpaci", "xpacd"]
KEY_NAMES = {
    (1, 0): "APIAKeyLo_EL1", (1, 1): "APIAKeyHi_EL1", (1, 2): "APIBKeyLo_EL1", (1, 3): "APIBKeyHi_EL1",
    (2, 0): "APDAKeyLo_EL1", (2, 1): "APDAKeyHi_EL1", (2, 2): "APDBKeyLo_EL1", (2, 3): "APDBKeyHi_EL1",
    (3, 0): "APGAKeyLo_EL1", (3, 1): "APGAKeyHi_EL1",
}


def classify(w):
    """Return (kind, replacement, mnemonic) for one instruction word.

    kind is None for anything that is not a pointer authentication instruction.
    replacement is None when the word stays as it is: HINT-space forms, which
    already execute as NOPs, and forms that have no single-instruction equivalent.
    """
    # HINT space: 1101 0101 0000 0011 0010 CRm op2 11111
    if (w & 0xFFFFF01F) == 0xD503201F:
        name = HINT_NAMES.get((w >> 5) & 0x7F)
        if name:
            return "hint", None, name
        return None, None, None
    # RETAA / RETAB, ERETAA / ERETAB
    if (w & 0xFFFFFBFF) == 0xD65F0BFF:
        return "ret", RET, "retab" if w & 0x400 else "retaa"
    if (w & 0xFFFFFBFF) == 0xD69F0BFF:
        return "eret", ERET, "eretab" if w & 0x400 else "eretaa"
    # BRAA / BRAB / BLRAA / BLRAB with modifier register, and the zero-modifier forms
    if (w & 0xFEDFF800) == 0xD61F0800:
        with_modifier = (w >> 24) & 1
        link = (w >> 21) & 1
        key_b = (w >> 10) & 1
        rn = (w >> 5) & 31
        rm = w & 31
        if with_modifier or rm == 31:
            name = ("blra" if link else "bra") + ("b" if key_b else "a") + ("" if with_modifier else "z")
            base = 0xD63F0000 if link else 0xD61F0000
            return ("blr" if link else "br"), base | (rn << 5), name
        return None, None, None
    # Data processing (1 source): PACIA ... AUTDZB, XPACI, XPACD
    if (w & 0xFFFF0000) == 0xDAC10000:
        opcode = (w >> 10) & 0x3F
        rn = (w >> 5) & 31
        if opcode <= 7 or (8 <= opcode <= 17 and rn == 31):
            return "strip", NOP, DP1_NAMES[opcode]
        return None, None, None
    # PACGA Xd, Xn, Xm|SP
    if (w & 0xFFE0FC00) == 0x9AC03000:
        rn = (w >> 5) & 31
        rd = w & 31
        if rd == 31:
            return "pacga", NOP, "pacga"  # result discarded; AND with Rd=31 would write SP
        return "pacga", 0x92607C00 | (rn << 5) | rd, "pacga"
    # LDRAA / LDRAB Xt, [Xn|SP, #simm10 * 8]{!}
    if (w & 0xFF200400) == 0xF8200400:
        key_b = (w >> 23) & 1
        sign = (w >> 22) & 1
        imm9 = (w >> 12) & 0x1FF
        writeback = (w >> 11) & 1
        rn = (w >> 5) & 31
        rt = w & 31
        offset = ((sign << 9) | imm9)
        if offset & 0x200:
            offset -= 0x400
        offset *= 8
        name = "ldrab" if key_b else "ldraa"
        if writeback:
            if -256 <= offset <= 255:
                return "ldra", 0xF8400C00 | ((offset & 0x1FF) << 12) | (rn << 5) | rt, name
            return "ldra-unconvertible", None, name
        if offset >= 0:
            return "ldra", 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt, name
        if offset >= -256:
            return "ldra", 0xF8400000 | ((offset & 0x1FF) << 12) | (rn << 5) | rt, name
        return "ldra-unconvertible", None, name
    # MSR / MRS of the ten key registers: op0=3, op1=0, CRn=2, CRm=1..3
    if (w & 0xFFDFF000) == 0xD5182000:
        crm = (w >> 8) & 15
        op2 = (w >> 5) & 7
        rt = w & 31
        name = KEY_NAMES.get((crm, op2))
        if name:
            if w & 0x00200000:  # MRS
                return "keymrs", (NOP if rt == 31 else 0xD2800000 | rt), "mrs " + name
            return "keymsr", NOP, "msr " + name
    return None, None, None


# --------------------------------------------------------------------------
# Container parsing


class Image:
    def __init__(self, base, label):
        self.base = base            # file offset of the mach_header_64
        self.label = label
        self.embedded = False       # located inside another image
        self.filetype = 0
        self.commands = []          # (cmd, file offset, size)
        self.segments = []
        self.data_in_code = []      # (file offset, length)


def parse_image(data, base, label, offset_origin):
    """Parse one 64-bit little-endian Mach-O header located at file offset base.

    offset_origin is added to file offsets stored in load commands.
    """
    if base + 32 > len(data):
        raise ValueError("%s: truncated Mach-O header" % label)
    magic, cputype, _, filetype, ncmds, sizeofcmds, _ = struct.unpack_from("<7I", data, base)
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64:
        return None
    image = Image(base, label)
    image.filetype = filetype
    pos = base + 32
    end = pos + sizeofcmds
    if end > len(data) or ncmds > 65536:
        raise ValueError("%s: load commands exceed the file" % label)
    for _ in range(ncmds):
        if pos + 8 > end:
            raise ValueError("%s: truncated load command" % label)
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or pos + size > end:
            raise ValueError("%s: invalid load command" % label)
        image.commands.append((cmd, pos, size))
        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, fileoff, filesize, _, initprot, nsects, _ = struct.unpack_from(
                "<16sQQQQiiII", data, pos + 8)
            if size != 72 + 80 * nsects:
                raise ValueError("%s: invalid section table" % label)
            segment = dict(name=segname.rstrip(b"\0").decode("latin-1"), vmaddr=vmaddr, vmsize=vmsize,
                           fileoff=fileoff + offset_origin, filesize=filesize, initprot=initprot, sections=[])
            for i in range(nsects):
                at = pos + 72 + 80 * i
                sectname, sseg, addr, ssize, soff, _, _, _, flags = struct.unpack_from(
                    "<16s16sQQIIIII", data, at)
                segment["sections"].append(dict(
                    name=sectname.rstrip(b"\0").decode("latin-1"),
                    segname=sseg.rstrip(b"\0").decode("latin-1"),
                    addr=addr, size=ssize, offset=soff + offset_origin if soff else 0, flags=flags))
            image.segments.append(segment)
        elif cmd == LC_DATA_IN_CODE:
            off, dsize = struct.unpack_from("<II", data, pos + 8)
            off += offset_origin
            if off + dsize <= len(data):
                for i in range(dsize // 8):
                    entry_off, length, _ = struct.unpack_from("<IHH", data, off + 8 * i)
                    image.data_in_code.append((entry_off + offset_origin, length))
        pos += size
    return image


def vm_to_file(segments, address, length):
    for s in segments:
        if s["vmaddr"] <= address and address + length <= s["vmaddr"] + s["filesize"]:
            return s["fileoff"] + address - s["vmaddr"]
    return None


def find_images(data):
    """Return every arm64 Mach-O image in the file, including embedded ones."""
    images = []
    if len(data) < 8:
        raise ValueError("file too small")
    magic_be, = struct.unpack_from(">I", data, 0)
    tops = []
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        count, = struct.unpack_from(">I", data, 4)
        if count > 64:
            raise ValueError("unreasonable fat header")
        for i in range(count):
            if magic_be == FAT_MAGIC:
                cputype, _, off, size, _ = struct.unpack_from(">iiIII", data, 8 + 20 * i)
            else:
                cputype, _, off, size, _, _ = struct.unpack_from(">iiQQII", data, 8 + 32 * i)
            if cputype == CPU_TYPE_ARM64:
                tops.append((off, "slice@%#x" % off))
    else:
        tops.append((0, "image"))
    for base, label in tops:
        top = parse_image(data, base, label, base)
        if top is None:
            continue
        images.append(top)
        # MH_FILESET kernel collections
        for cmd, pos, size in top.commands:
            if cmd == LC_FILESET_ENTRY and size >= 32:
                _, fileoff, name_at, _ = struct.unpack_from("<QQII", data, pos + 8)
                raw = data[pos + name_at:pos + size].split(b"\0", 1)[0].decode("latin-1")
                inner = parse_image(data, base + fileoff, raw, base)
                if inner is not None:
                    inner.embedded = True
                    images.append(inner)
        # Kernel images that list embedded Mach-O headers by virtual address
        for segment in top.segments:
            for section in segment["sections"]:
                if section["name"] == "__macho_list" and section["size"] % 8 == 0:
                    at = vm_to_file(top.segments, section["addr"], section["size"])
                    if at is None:
                        continue
                    for i in range(section["size"] // 8):
                        header_va, = struct.unpack_from("<Q", data, at + 8 * i)
                        header_at = vm_to_file(top.segments, header_va, 32)
                        if header_at is None:
                            continue
                        inner = parse_image(data, header_at, "embedded@%#x" % header_va, 0)
                        if inner is None:
                            continue
                        # Section file offsets are derived from the outer mapping.
                        for seg in inner.segments:
                            seg["fileoff"] = vm_to_file(top.segments, seg["vmaddr"], 1) or 0
                            for sec in seg["sections"]:
                                where = vm_to_file(top.segments, sec["addr"], max(sec["size"], 1))
                                sec["offset"] = where or 0
                        inner.data_in_code = []
                        inner.embedded = True
                        images.append(inner)
    return images


def code_ranges(data, image):
    """Yield (file offset, size, address, 'segment,section') for instruction sections."""
    for segment in image.segments:
        for section in segment["sections"]:
            if (section["flags"] & 0xFF) in ZEROFILL_TYPES or not section["size"]:
                continue
            if not section["flags"] & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
                continue
            offset = section["offset"]
            if not offset or offset + section["size"] > len(data):
                continue
            yield offset, section["size"], section["addr"], "%s,%s" % (section["segname"], section["name"])


def elf_code_ranges(data):
    """ELF64 little-endian executable sections; used by the functional tests."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, _ = struct.unpack_from("<HHH", data, 0x3A)
    for i in range(shnum):
        at = shoff + i * shentsize
        _, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, at)
        if sh_type == 1 and sh_flags & 4 and sh_size:
            yield sh_offset, sh_size, sh_addr, "elf-exec-%d" % i


# --------------------------------------------------------------------------
# corecrypto integrity fields


def fips_fields(data, image):
    """Yield (hmac offset, text offset, text size, label) for provider integrity fields.

    The text offset is None when the image holds an integrity field that cannot be
    attributed to exactly one text section. Such a field is reported as not
    resealed, so that a rewritten image is never passed on with a stale value.
    """
    sections = [s for seg in image.segments for s in seg["sections"]]
    integrity = [s for s in sections if s["name"] == "__fips_hmacs" and s["size"]]
    if not integrity:
        return
    # Same choice as scripts/seal_macos26_crypto.py: the first provider section of __TEXT or __TEXT_EXEC.
    text = [s for s in sections if s["name"] == "__cc26_text" and s["segname"] in ("__TEXT", "__TEXT_EXEC")][:1]
    if not text:
        text = [s for s in sections if s["name"] == "__text" and s["segname"] in ("__TEXT_EXEC", "__TEXT")]
    field = integrity[0]
    usable = (len(integrity) == 1 and field["size"] == 32 and field["offset"]
              and field["offset"] + 32 <= len(data) and len(text) == 1 and text[0]["offset"]
              and text[0]["offset"] + text[0]["size"] <= len(data))
    if not usable:
        yield field["offset"] or 0, None, 0, image.label
        return
    yield field["offset"], text[0]["offset"], text[0]["size"], image.label


def provider_hmac(data, offset, size):
    return hmac.digest(bytes(32), bytes(data[offset:offset + size]), "sha256")


# --------------------------------------------------------------------------
# Scan and rewrite


def site_description(image, segment, at, word):
    """Where an uncovered authenticated return sits: segment, enclosing section and flags."""
    address = segment["vmaddr"] + at - segment["fileoff"]
    entry = dict(image=image.label, segment=segment["name"], initprot=segment["initprot"],
                 file_offset=at, address="%#x" % address, word="%#010x" % word,
                 mnemonic="retaa" if word == 0xD65F0BFF else "retab", section=None)
    for section in segment["sections"]:
        if section["addr"] <= address < section["addr"] + section["size"]:
            entry["section"] = section["name"]
            entry["section_flags"] = "%#010x" % section["flags"]
            break
    return entry


def describe_site(site):
    section = site["section"] or "(no section)"
    flags = (" flags %s" % site["section_flags"]) if site.get("section_flags") else ""
    return "%s %s,%s%s initprot %d file %#x addr %s %s" % (
        site["image"], site["segment"], section, flags, site["initprot"], site["file_offset"],
        site["address"], site["mnemonic"])


def process(data, rewrite):
    """Scan (and optionally rewrite in place) a bytearray. Returns the report."""
    report = dict(images=[], totals={}, unconvertible=[], hmac=[], changed_words=0,
                  image_labels=[], uncovered_executable_returns=0, uncovered_return_sites=[])
    totals = report["totals"]
    ranges = []
    seals = []
    if data[:4] == b"\x7fELF":
        ranges = [(o, s, a, n, "elf") for o, s, a, n in elf_code_ranges(data)]
        images = []
    else:
        images = find_images(data)
        if not images:
            raise ValueError("no arm64 Mach-O image found")
        report["image_labels"] = [image.label for image in images]
        for image in images:
            skip = sorted(image.data_in_code)
            for offset, size, address, name in code_ranges(data, image):
                ranges.append((offset, size, address, name, image.label, skip))
            for field in fips_fields(data, image):
                hmac_at, text_at, text_size, label = field
                if text_at is None:
                    seals.append((hmac_at, None, 0, label, False, b""))
                    continue
                stored = bytes(data[hmac_at:hmac_at + 32])
                matches = stored == provider_hmac(data, text_at, text_size)
                seals.append((hmac_at, text_at, text_size, label, matches, stored))
    seen = set()
    for entry in ranges:
        offset, size, address, name, label = entry[:5]
        skip = entry[5] if len(entry) > 5 else []
        if (offset, size) in seen:
            continue
        seen.add((offset, size))
        counts = {}
        start = offset + ((-address) & 3)
        end = offset + size - ((offset + size - start) & 3)
        excluded = [(a, a + n) for a, n in skip if a < end and a + n > start]
        words = struct.unpack_from("<%dI" % ((end - start) // 4), data, start)
        for index, w in enumerate(words):
            # Cheap pre-filter: every pattern handled here has one of these top bytes.
            top = w >> 24
            if top not in (0xD5, 0xD6, 0xD7, 0xDA, 0x9A, 0xF8):
                continue
            kind, replacement, mnemonic = classify(w)
            if kind is None:
                continue
            at = start + 4 * index
            if excluded and any(a <= at < b for a, b in excluded):
                counts["data-in-code-skipped"] = counts.get("data-in-code-skipped", 0) + 1
                continue
            key = kind + ":" + mnemonic
            counts[key] = counts.get(key, 0) + 1
            if kind == "ldra-unconvertible":
                report["unconvertible"].append(dict(
                    image=label, section=name, address="%#x" % (address + at - offset),
                    file_offset=at, word="%#010x" % w, mnemonic=mnemonic))
            if rewrite and replacement is not None and replacement != w:
                struct.pack_into("<I", data, at, replacement)
                report["changed_words"] += 1
        if counts:
            report["images"].append(dict(image=label, section=name, address="%#x" % address,
                                         bytes=size, counts=dict(sorted(counts.items()))))
        for key, value in counts.items():
            totals[key] = totals.get(key, 0) + value
    # Safety net: authenticated returns in executable segments that no instruction
    # section covers mean that some code was not found (for example a component
    # whose embedded header was not located). The exact RETAA / RETAB words are
    # practically never data.
    covered = sorted(seen)
    for image in images:
        if image.embedded:
            continue
        for segment in image.segments:
            if not segment.get("initprot", 0) & 4 or not segment["filesize"]:
                continue
            start = segment["fileoff"]
            end = min(start + segment["filesize"], len(data))
            start += (-start) & 3
            position = start
            gaps = []
            for lo, size in covered:
                hi = lo + size
                if hi <= position or lo >= end:
                    continue
                if lo > position:
                    gaps.append((position, lo))
                position = max(position, hi)
            if position < end:
                gaps.append((position, end))
            for lo, hi in gaps:
                lo += (-lo) & 3
                if hi - lo < 4:
                    continue
                for index, w in enumerate(struct.unpack_from("<%dI" % ((hi - lo) // 4), data, lo)):
                    if w == 0xD65F0FFF or w == 0xD65F0BFF:
                        report["uncovered_executable_returns"] += 1
                        if len(report["uncovered_return_sites"]) < 64:
                            at = lo + 4 * index
                            report["uncovered_return_sites"].append(
                                site_description(image, segment, at, w))
    report["totals"] = dict(sorted(totals.items()))
    summary = {}
    for key, value in totals.items():
        summary[key.split(":")[0]] = summary.get(key.split(":")[0], 0) + value
    report["summary"] = dict(sorted(summary.items()))
    for hmac_at, text_at, text_size, label, matched, stored in seals:
        entry = dict(image=label, hmac_file_offset=hmac_at, text_file_offset=text_at, text_bytes=text_size,
                     stored=stored.hex(), stored_matches_original_text=matched, resealed=False)
        if text_at is None:
            entry["reason"] = "integrity field cannot be attributed to exactly one text section"
        if rewrite and matched:
            fresh = provider_hmac(data, text_at, text_size)
            data[hmac_at:hmac_at + 32] = fresh
            entry.update(resealed=True, new=fresh.hex())
        report["hmac"].append(entry)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    scan = sub.add_parser("scan", help="count pointer authentication instructions")
    scan.add_argument("input")
    scan.add_argument("--json")
    rewrite = sub.add_parser("rewrite", help="write a copy with the instructions rewritten")
    rewrite.add_argument("input")
    rewrite.add_argument("output")
    rewrite.add_argument("--json")
    rewrite.add_argument("--mark", action="store_true",
                         help='store "NPAC" in mach_header_64.reserved of the outer image')
    rewrite.add_argument("--no-reseal", action="store_true",
                         help="leave corecrypto integrity fields untouched")
    args = parser.parse_args()
    with open(args.input, "rb") as stream:
        data = bytearray(stream.read())
    before = hashlib.sha256(data).hexdigest()
    if args.action == "scan":
        report = process(data, rewrite=False)
    else:
        if args.no_reseal:
            original = bytes(data)
        report = process(data, rewrite=True)
        if args.no_reseal:
            for entry in report["hmac"]:
                if entry["text_file_offset"] is None:
                    continue
                at = entry["hmac_file_offset"]
                data[at:at + 32] = original[at:at + 32]
                entry["resealed"] = False
        if args.mark:
            if data[:4] != struct.pack("<I", MH_MAGIC_64):
                raise SystemExit("--mark requires a thin Mach-O image")
            struct.pack_into("<I", data, 28, MARK)
            report["marked"] = True
        with open(args.output, "wb") as stream:
            stream.write(data)
        report["output_sha256"] = hashlib.sha256(data).hexdigest()
    report["input_sha256"] = before
    report["input_bytes"] = len(data)
    if args.json:
        with open(args.json, "w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print("input   %s  %d bytes" % (before, len(data)))
    for key, value in report["summary"].items():
        print("  %-22s %9d" % (key, value))
    if report["unconvertible"]:
        print("  sites without a one-instruction equivalent: %d" % len(report["unconvertible"]))
    if report["uncovered_executable_returns"]:
        print("  WARNING: %d authenticated returns in executable bytes that no instruction section covers"
              % report["uncovered_executable_returns"])
        for site in report["uncovered_return_sites"][:20]:
            print("    %s" % describe_site(site))
    for entry in report["hmac"]:
        if entry["text_file_offset"] is None:
            print("  integrity field in %s: %s" % (entry["image"], entry["reason"]))
            continue
        print("  integrity field in %s: stored value %s the text%s" % (
            entry["image"], "matches" if entry["stored_matches_original_text"] else "does NOT match",
            ", resealed" if entry["resealed"] else ""))
    if args.action == "rewrite":
        print("changed %d words" % report["changed_words"])
        print("output  %s" % report["output_sha256"])


if __name__ == "__main__":
    main()

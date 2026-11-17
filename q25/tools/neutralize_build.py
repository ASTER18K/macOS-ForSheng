#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Produce a PAC-neutral copy of a macOS-ForSheng kernel build directory.

The input is a directory as written by scripts/build_macos26_xnu.py or by
scripts/emit_macos26_security.py: kernel.development.sheng, build.json and,
for candidates with Apple components, security-relink.json. The output is a new
directory with the same layout in which

  * every PAC instruction outside the HINT space is replaced by its identity
    equivalent (pac_neutralize.py), including the embedded components,
  * corecrypto integrity fields are recomputed,
  * mach_header_64.reserved carries the "NPAC" marker that the patched
    DarwinBoot loader requires on CPUs without pointer authentication,
  * the hashes recorded in build.json and security-relink.json describe the
    rewritten image, so the existing observation scripts accept it.

Symbols, the link map and the dSYM stay valid: no instruction moves.

Usage: neutralize_build.py INPUT_DIR OUTPUT_DIR
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pac_neutralize  # noqa: E402

KERNEL = "kernel.development.sheng"


def sha256_file(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_dir")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    source = os.path.abspath(args.input_dir)
    target = os.path.abspath(args.output_dir)
    if os.path.exists(target):
        raise SystemExit("output directory exists; choose a new one")
    kernel_path = os.path.join(source, KERNEL)
    build_path = os.path.join(source, "build.json")
    with open(build_path) as stream:
        build = json.load(stream)
    with open(kernel_path, "rb") as stream:
        data = bytearray(stream.read())
    before = hashlib.sha256(data).hexdigest()
    if build.get("executable_kernel_sha256") != before:
        raise SystemExit("kernel differs from the hash recorded in build.json")
    if build.get("architecture") != "arm64e":
        raise SystemExit("only arm64e builds contain pointer authentication instructions")
    if build.get("pac_neutral"):
        raise SystemExit("this build is already PAC-neutral")
    relink_path = os.path.join(source, "security-relink.json")
    relink = None
    if os.path.isfile(relink_path):
        with open(relink_path) as stream:
            relink = json.load(stream)
        if relink.get("candidate_sha256") != before:
            raise SystemExit("security-relink.json describes a different candidate")

    report = pac_neutralize.process(data, rewrite=True)
    if report["unconvertible"]:
        raise SystemExit("%d authenticated loads have no one-instruction equivalent; "
                         "kernel text cannot be left to trap" % len(report["unconvertible"]))
    if report["uncovered_executable_returns"]:
        sites = "".join("\n  " + pac_neutralize.describe_site(site)
                        for site in report["uncovered_return_sites"][:20])
        raise SystemExit("%d authenticated returns lie outside every instruction section; "
                         "some code was not located%s" % (report["uncovered_executable_returns"], sites))
    if relink is not None:
        embedded = len(report["image_labels"]) - 1
        expected = len(relink.get("modules", {})) + (1 if relink.get("storage_driver") else 0)
        if embedded < expected:
            raise SystemExit("found %d embedded images but the candidate records %d components"
                             % (embedded, expected))
    unsealed = [entry for entry in report["hmac"] if not entry["resealed"]]
    if unsealed:
        raise SystemExit("an integrity field did not match its text before rewriting: %r" % unsealed)
    struct.pack_into("<I", data, 28, pac_neutralize.MARK)
    leftover = pac_neutralize.process(bytearray(data), rewrite=False)["summary"]
    if set(leftover) - {"hint"}:
        raise SystemExit("PAC instructions remain after rewriting: %r" % leftover)
    after = hashlib.sha256(data).hexdigest()

    os.makedirs(target)
    for name in os.listdir(source):
        if name in (KERNEL, "build.json", "security-relink.json"):
            continue
        path = os.path.join(source, name)
        if os.path.isdir(path):
            shutil.copytree(path, os.path.join(target, name))
        else:
            shutil.copy2(path, os.path.join(target, name))
    with open(os.path.join(target, KERNEL), "wb") as stream:
        stream.write(data)
    with open(os.path.abspath(pac_neutralize.__file__), "rb") as stream:
        tool_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    build["executable_kernel_sha256"] = after
    build["pac_neutral"] = dict(
        marker="NPAC", tool_sha256=tool_hash, source_kernel_sha256=before,
        changed_words=report["changed_words"], summary=report["summary"],
        integrity_fields=[dict(image=e["image"], text_bytes=e["text_bytes"], old=e["stored"], new=e.get("new"))
                          for e in report["hmac"]],
        requires_cpu_without_pointer_authentication=True, runtime_qualified=False)
    # The build record of the native provider seal describes the image; keep it describing this one.
    seal = build.get("corecrypto_integrity")
    if isinstance(seal, dict):
        for entry in report["hmac"]:
            if entry["stored"] == seal.get("hmac_sha256") and entry.get("new"):
                seal.update(hmac_sha256=entry["new"], kernel_sha256=after,
                            pac_neutral_source_hmac_sha256=entry["stored"])
    with open(os.path.join(target, "build.json"), "w") as stream:
        json.dump(build, stream, indent=2)
        stream.write("\n")
    if relink is not None:
        relink["candidate_sha256"] = after
        relink["pac_neutral_source_candidate_sha256"] = before
        with open(os.path.join(target, "security-relink.json"), "w") as stream:
            json.dump(relink, stream, indent=2)
            stream.write("\n")
    with open(os.path.join(target, "pac-neutral.json"), "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("source kernel  %s" % before)
    print("neutral kernel %s" % after)
    for key, value in report["summary"].items():
        print("  %-10s %9d" % (key, value))
    print("changed %d words, %d integrity field(s) recomputed" % (report["changed_words"], len(report["hmac"])))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Download the Kernel Debug Kit pinned in config/macos26.json and verify it.

The URL, size and SHA-256 come from the "kdk" entry of the configuration file.
An existing file with the right size and hash is kept.

Usage: fetch_kdk.py CONFIG_JSON OUTPUT_DIR
"""
import hashlib
import json
import os
import sys
import urllib.request


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    with open(sys.argv[1]) as stream:
        pin = json.load(stream)["kdk"]
    name = os.path.basename(pin["filename"])
    if name != pin["filename"] or not pin["url"].startswith("https://"):
        raise SystemExit("unexpected Kernel Debug Kit entry in the configuration")
    os.makedirs(sys.argv[2], exist_ok=True)
    target = os.path.join(sys.argv[2], name)
    if not (os.path.isfile(target) and os.path.getsize(target) == pin["bytes"] and digest(target) == pin["sha256"]):
        partial = target + ".part"
        with urllib.request.urlopen(pin["url"]) as response, open(partial, "wb") as out:
            while True:
                block = response.read(1 << 22)
                if not block:
                    break
                out.write(block)
        if os.path.getsize(partial) != pin["bytes"] or digest(partial) != pin["sha256"]:
            os.remove(partial)
            raise SystemExit("downloaded file differs from the pinned size or SHA-256")
        os.replace(partial, target)
    print("%s  %s  %d bytes" % (pin["sha256"], target, pin["bytes"]))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stream an Apple pbzx payload, list its cpio entries and extract selected files.

A Kernel Debug Kit disk image holds KernelDebugKit.pkg; inside it, KDK.pkg/Payload
is a pbzx stream of a cpio archive. 7-Zip opens the disk image and the package:

  7z e -y -opkg Kernel_Debug_Kit_*.dmg "Kernel Debug Kit/KernelDebugKit.pkg"
  7z e -y -oxar pkg/KernelDebugKit.pkg KDK.pkg/Payload

Usage:
  kdk_extract.py list PAYLOAD
  kdk_extract.py extract PAYLOAD OUTDIR REGEX [REGEX ...]

Only regular files whose path matches one of the regular expressions are written.
Paths are sanitised and always stay below OUTDIR.
"""
import lzma
import os
import re
import struct
import sys

XZ_MAGIC = b"\xfd7zXZ\x00"


def pbzx_chunks(stream):
    if stream.read(4) != b"pbzx":
        raise ValueError("not a pbzx stream")
    stream.read(8)  # chunk size hint
    while True:
        head = stream.read(16)
        if len(head) < 16:
            return
        flags_or_len, packed = struct.unpack(">QQ", head)
        data = stream.read(packed)
        if len(data) != packed:
            raise ValueError("truncated pbzx chunk")
        if data[:6] == XZ_MAGIC:
            yield lzma.decompress(data)
        else:
            yield data


class ChunkReader:
    def __init__(self, chunks):
        self.chunks = chunks
        self.buf = b""
        self.pos = 0

    def read(self, n):
        out = []
        need = n
        while need > 0:
            avail = len(self.buf) - self.pos
            if avail == 0:
                try:
                    self.buf = next(self.chunks)
                except StopIteration:
                    break
                self.pos = 0
                continue
            take = min(avail, need)
            out.append(self.buf[self.pos:self.pos + take])
            self.pos += take
            need -= take
        return b"".join(out)

    def skip(self, n):
        while n > 0:
            avail = len(self.buf) - self.pos
            if avail == 0:
                try:
                    self.buf = next(self.chunks)
                except StopIteration:
                    raise ValueError("truncated cpio stream")
                self.pos = 0
                continue
            take = min(avail, n)
            self.pos += take
            n -= take


def cpio_entries(reader):
    """Yield (name, mode, size) and leave the reader positioned at the file data."""
    while True:
        magic = reader.read(6)
        if len(magic) < 6:
            return
        if magic == b"070707":  # odc
            rest = reader.read(70)
            fields = [int(rest[a:b], 8) for a, b in
                      ((0, 6), (6, 12), (12, 18), (18, 24), (24, 30), (30, 36), (36, 42), (42, 53))]
            mode = fields[2]
            namesize = int(rest[53:59], 8)
            filesize = int(rest[59:70], 8)
            name = reader.read(namesize)[:-1].decode("utf-8", "replace")
        elif magic in (b"070701", b"070702"):  # newc
            rest = reader.read(104)
            vals = [int(rest[i:i + 8], 16) for i in range(0, 104, 8)]
            mode, filesize, namesize = vals[1], vals[6], vals[11]
            name = reader.read(namesize)[:-1].decode("utf-8", "replace")
            pad = (4 - (110 + namesize) % 4) % 4
            reader.skip(pad)
            if name == "TRAILER!!!":
                return
            yield name, mode, filesize
            reader.skip((4 - filesize % 4) % 4)
            continue
        else:
            raise ValueError("unknown cpio magic %r" % magic)
        if name == "TRAILER!!!":
            return
        yield name, mode, filesize


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("list", "extract"):
        raise SystemExit(__doc__)
    action, payload = sys.argv[1], sys.argv[2]
    patterns = []
    outdir = None
    if action == "extract":
        if len(sys.argv) < 5:
            raise SystemExit(__doc__)
        outdir = os.path.abspath(sys.argv[3])
        patterns = [re.compile(p) for p in sys.argv[4:]]
    with open(payload, "rb") as stream:
        reader = ChunkReader(pbzx_chunks(stream))
        total = count = 0
        for name, mode, size in cpio_entries(reader):
            is_file = (mode & 0o170000) == 0o100000
            is_link = (mode & 0o170000) == 0o120000
            if action == "list":
                kind = "f" if is_file else ("l" if is_link else "d")
                print("%s %12d %s" % (kind, size, name))
                reader.skip(size)
            else:
                if is_file and any(p.search(name) for p in patterns):
                    clean = os.path.normpath("/" + name).lstrip("/")
                    dest = os.path.join(outdir, clean)
                    if not dest.startswith(outdir + os.sep):
                        raise ValueError("path escapes output directory: %r" % name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    left = size
                    with open(dest, "wb") as out:
                        while left > 0:
                            piece = reader.read(min(left, 1 << 22))
                            if not piece:
                                raise ValueError("truncated file data")
                            out.write(piece)
                            left -= len(piece)
                    print("extracted %12d %s" % (size, clean))
                    count += 1
                    total += size
                else:
                    reader.skip(size)
        if action == "extract":
            print("files: %d, bytes: %d" % (count, total))


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # The reader of a listing went away (for example "| head"); that is not an error.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())

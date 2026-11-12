#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run every self-test of the PAC fallback for CPUs without pointer authentication.
#
# No Apple input is needed for the default set. Tools: python3, clang, ld.lld,
# llvm-mc, llvm-objdump, a native C compiler, aarch64-linux-gnu-gcc with a
# static C library, and qemu-aarch64-static (or qemu-aarch64).
# On Ubuntu 24.04: clang lld llvm gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user-static
#
# With KDK_ROOT set to the directory that holds System/Library/{Kernels,Extensions}
# of an extracted Kernel Debug Kit (see tools/kdk_extract.py), the tests that use
# real Apple kernel code run as well.
set -u
here=$(cd "$(dirname "$0")" && pwd)
status=0
step() { # label command...
  local label=$1
  shift
  echo "=== $label"
  if "$@"; then echo "--- $label: passed"; else echo "--- $label: FAILED"; status=1; fi
  echo
}
step "instruction encodings against the LLVM assembler" python3 -I "$here/test_encodings.py"
step "kernel decoder against the Python classifier" python3 -I "$here/emul/test_decoder_equivalence.py"
step "kernel headers against mock declarations" bash "$here/kernel/run.sh"
step "native provider integrity field" python3 -I "$here/test_native_seal.py"
step "rewritten programs on emulated CPUs" bash "$here/exec/run.sh"
step "trap, emulate and patch on emulated CPUs" bash "$here/emul/run.sh"
if [ -n "${KDK_ROOT:-}" ]; then
  kernels="$KDK_ROOT/System/Library/Kernels"
  extensions="$KDK_ROOT/System/Library/Extensions"
  step "embedded components and integrity field (real corecrypto and apfs)" \
    python3 -I "$here/test_container.py" "$extensions"
  step "classifier against the LLVM disassembler (kernel.release.t8103)" \
    python3 -I "$here/crosscheck_objdump.py" "$kernels/kernel.release.t8103"
  step "kernel decoder against the Python classifier (kernel.release.t8103)" \
    python3 -I "$here/emul/test_decoder_equivalence.py" "$kernels/kernel.release.t8103"
else
  echo "KDK_ROOT is not set: tests on real Apple kernel code skipped"
fi
if [ "$status" = "0" ]; then echo "ALL TEST GROUPS PASSED"; else echo "SOME TEST GROUPS FAILED"; fi
exit "$status"

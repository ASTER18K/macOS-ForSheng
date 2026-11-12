#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Trap-and-emulate test of platform/sheng/macos26/pac/a64e/a64e.h under QEMU user-mode emulation.
# Needs: aarch64-linux-gnu-gcc with a static C library, qemu-aarch64-static (or qemu-aarch64).
set -u
here=$(cd "$(dirname "$0")" && pwd)
qemu=$(command -v qemu-aarch64-static || command -v qemu-aarch64) || { echo "qemu-aarch64 not found"; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
# The handler must not contain PAC instructions itself, exactly like the kernel exception path.
aarch64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -march=armv8.2-a -mbranch-protection=none \
  -c -o "$work/trap_harness.o" "$here/trap_harness.c" || exit 2
aarch64-linux-gnu-gcc -march=armv8.3-a -DAS_FUNCTION -c -o "$work/pac_body.o" "$here/../exec/pac_exec.S" || exit 2
aarch64-linux-gnu-gcc -static -o "$work/trap_harness" "$work/trap_harness.o" "$work/pac_body.o" || exit 2
echo "qemu: $("$qemu" --version | head -n 1)"
# Host unit test of the executor (sanitizers when the host compiler provides them).
if cc -std=c99 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -o "$work/test_execute" "$here/test_execute.c" 2>/dev/null ||
   cc -std=c99 -O1 -g -Wall -Wextra -Werror -o "$work/test_execute" "$here/test_execute.c"; then
  if "$work/test_execute"; then echo "[OK]   host executor unit test"; else echo "[NG]   host executor unit test"; fail=1; fi
else
  echo "[NG]   host executor unit test did not build"; fail=1
fi
check() { # cpu mode expected-exit expected-last-line
  local out status last
  out=$("$qemu" -cpu "$1" "$work/trap_harness" "$2" 2>&1)
  status=$?
  last=$(printf '%s\n' "$out" | tail -n 1)
  if [ "$status" = "$3" ] && { [ -z "$4" ] || [ "$last" = "$4" ]; }; then
    echo "[OK]   $1 $2: exit $status"
  else
    echo "[NG]   $1 $2: exit $status, expected $3"
    fail=1
  fi
  printf '%s\n' "$out" | grep -E "^pass|^total" | sed 's/^/         /'
}
check max native 0 "HARNESS OK"
for cpu in cortex-a55 cortex-a76 max,pauth=off; do
  check "$cpu" native 132 ""
  check "$cpu" emulate 0 "HARNESS OK"
  check "$cpu" patch 0 "HARNESS OK"
done
if [ "$fail" = "0" ]; then echo "RESULT: all checks passed"; else echo "RESULT: FAILED"; fi
exit "$fail"

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Functional test of pac_neutralize.py under QEMU user-mode emulation.
# Needs: clang, ld.lld, qemu-aarch64-static (or qemu-aarch64), python3.
set -u
here=$(cd "$(dirname "$0")" && pwd)
tool="$here/../../tools/pac_neutralize.py"
qemu=$(command -v qemu-aarch64-static || command -v qemu-aarch64) || { echo "qemu-aarch64 not found"; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0

clang --target=aarch64-linux-gnu -march=armv8.3-a -c "$here/pac_exec.S" -o "$work/pac_exec.o" || exit 2
ld.lld -static -e _start -o "$work/pac_exec" "$work/pac_exec.o" || exit 2
clang --target=aarch64-linux-gnu -march=armv8.3-a -mbranch-protection=pac-ret+b-key+leaf -O2 \
  -ffreestanding -fno-builtin -nostdlib -fno-stack-protector -c "$here/pac_c.c" -o "$work/pac_c.o" || exit 2
ld.lld -static -e _start -o "$work/pac_c" "$work/pac_c.o" || exit 2

run() { # cpu binary -> prints "status|output"
  local out status
  out=$("$qemu" -cpu "$1" "$2" 2>/dev/null)
  status=$?
  echo "$status|$out"
}
expect() { # label actual expected
  if [ "$2" = "$3" ]; then echo "[OK]   $1: $2"; else echo "[NG]   $1: got '$2', expected '$3'"; fail=1; fi
}

echo "qemu: $("$qemu" --version | head -n 1)"
echo "== original binaries on a CPU with pointer authentication (max)"
ref_exec=$(run max "$work/pac_exec")
ref_c=$(run max "$work/pac_c")
expect "pac_exec on max" "$ref_exec" "0|ALL OK"
case "$ref_c" in 0\|0x*) echo "[OK]   pac_c on max: $ref_c" ;; *) echo "[NG]   pac_c on max: $ref_c"; fail=1 ;; esac

echo "== original binaries on CPUs without pointer authentication"
for cpu in cortex-a55 cortex-a76; do
  got=$(run "$cpu" "$work/pac_exec")
  case "$got" in 132\|*) echo "[OK]   pac_exec on $cpu stops with SIGILL as expected" ;;
    *) echo "[NG]   pac_exec on $cpu: expected SIGILL, got $got"; fail=1 ;; esac
done

echo "== rewrite"
python3 -I "$tool" rewrite "$work/pac_exec" "$work/pac_exec.nopac" --json "$work/exec.json" > "$work/exec.log" || exit 2
python3 -I "$tool" rewrite "$work/pac_c" "$work/pac_c.nopac" --json "$work/c.json" > "$work/c.log" || exit 2
chmod +x "$work/pac_exec.nopac" "$work/pac_c.nopac"
grep -E "changed|without" "$work/exec.log" "$work/c.log" | sed 's|.*/||'
unconv=$(python3 -I -c "import json,sys; print(len(json.load(open(sys.argv[1]))['unconvertible']))" "$work/exec.json")
expect "sites reported as not convertible in pac_exec" "$unconv" "3"

echo "== rewritten binaries on CPUs without pointer authentication"
for cpu in cortex-a55 cortex-a76 max,pauth=off; do
  expect "pac_exec.nopac on $cpu" "$(run "$cpu" "$work/pac_exec.nopac")" "0|ALL OK"
  expect "pac_c.nopac on $cpu" "$(run "$cpu" "$work/pac_c.nopac")" "$ref_c"
done

echo "== second rewrite changes nothing"
python3 -I "$tool" rewrite "$work/pac_exec.nopac" "$work/pac_exec.nopac2" > "$work/again.log" || exit 2
expect "words changed by a second pass" "$(grep -oE 'changed [0-9]+' "$work/again.log")" "changed 0"

if [ "$fail" = "0" ]; then echo "RESULT: all checks passed"; else echo "RESULT: FAILED"; fi
exit "$fail"

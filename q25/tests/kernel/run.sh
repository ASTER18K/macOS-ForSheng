#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Syntax check of the staged kernel headers against mock declarations.
#
# The mocks copy signatures and field names from xnu-12377.121.6, and
# warnflags.txt is the warning set of makedefs/MakeInc.def with -Werror. This
# catches mistakes in the headers themselves; it does not replace the real
# kernel build, which uses Apple's compiler and the real headers.
# Needs: clang (any of clang, clang-18 ... clang-21).
set -u
here=$(cd "$(dirname "$0")" && pwd)
headers="$here/../../../platform/sheng/macos26/pac/a64e"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/arm64" "$work/vm" "$work/arm"
cp "$headers/a64e.h" "$work/arm64/sheng_a64e.h"
cp "$headers/a64e_kernel.h" "$work/arm64/sheng_a64e_kernel.h"
cp "$headers/a64e_vm.h" "$work/vm/sheng_a64e_vm.h"
: > "$work/arm64/proc_reg.h"
echo 'extern void cache_sync_page(ppnum_t pp);' > "$work/arm/caches_internal.h"
fail=0
found=0
seen=""
for cc in clang clang-18 clang-19 clang-20 clang-21; do
  path=$(command -v "$cc") || continue
  real=$(readlink -f "$path")
  case " $seen " in *" $real "*) continue ;; esac
  seen="$seen $real"
  found=1
  for unit in "mock_sleh.c -DMOCK_NONE" "mock_sleh.c -DMOCK_GENERAL_SETTERS" "mock_vm.c -DMOCK_NONE"; do
    file=${unit%% *}
    define=${unit##* }
    # shellcheck disable=SC2046
    if "$cc" --target=arm64e-apple-macos26.5 -ffreestanding -std=gnu11 -O2 -fsyntax-only \
      $(cat "$here/warnflags.txt") -I"$work" -I"$here" "$define" "$here/$file" 2> "$work/log"; then
      echo "[OK]   $("$cc" --version | head -n 1 | sed 's/ (.*//'): $unit"
    else
      echo "[NG]   $("$cc" --version | head -n 1 | sed 's/ (.*//'): $unit"
      head -n 20 "$work/log"
      fail=1
    fi
  done
done
if [ "$found" = "0" ]; then echo "clang not found"; exit 2; fi
if [ "$fail" = "0" ]; then echo "RESULT: all checks passed"; else echo "RESULT: FAILED"; fi
exit "$fail"

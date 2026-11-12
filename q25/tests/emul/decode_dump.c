/* SPDX-License-Identifier: MIT */
/* Reads little-endian 32-bit words from stdin and prints "kind replacement" per word. */
#include <stdio.h>
#include <stdint.h>
#include "../../../platform/sheng/macos26/pac/a64e/a64e.h"

int
main(void)
{
	static uint32_t buffer[1 << 16];
	static char line[1 << 20];
	size_t count;
	setvbuf(stdout, line, _IOFBF, sizeof(line));
	while ((count = fread(buffer, 4, sizeof(buffer) / 4, stdin)) > 0) {
		for (size_t i = 0; i < count; i++) {
			struct a64e_insn insn;
			a64e_decode(buffer[i], &insn);
			printf("%u %08x %d %u %u %u\n", insn.kind, insn.replacement, insn.offset,
			    insn.rn, insn.rt, insn.writeback);
		}
	}
	return 0;
}

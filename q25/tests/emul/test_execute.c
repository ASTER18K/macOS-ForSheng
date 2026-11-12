/* SPDX-License-Identifier: MIT */
/* Host unit test for a64e_execute(): identity semantics of every instruction kind. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../platform/sheng/macos26/pac/a64e/a64e.h"

static int failures;
static uint64_t memory[8] = {0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888};
#define MEMORY_BASE 0x10000ull

static int
load(void *context, uint64_t address, uint64_t *value)
{
	(void)context;
	if (address < MEMORY_BASE || address + 8 > MEMORY_BASE + sizeof(memory) || (address & 7)) {
		return 1;
	}
	*value = memory[(address - MEMORY_BASE) / 8];
	return 0;
}

static void
reset(struct a64e_regs *regs)
{
	for (int i = 0; i < 31; i++) {
		regs->x[i] = 0x1000 + (uint64_t)i * 0x10;
	}
	regs->sp = 0x7000;
	regs->pc = 0x4000;
}

#define CHECK(condition, name) do { \
	if (!(condition)) { printf("FAIL %s\n", name); failures++; } \
} while (0)

static int
step(uint32_t word, struct a64e_regs *regs, uint64_t *fault)
{
	struct a64e_insn insn;
	if (!a64e_decode(word, &insn)) {
		return -100;
	}
	return a64e_execute(&insn, regs, load, NULL, fault);
}

int
main(void)
{
	struct a64e_regs r, before;
	uint64_t fault = 0;

	reset(&r);                                   /* retab */
	CHECK(step(0xD65F0FFF, &r, &fault) == 1 && r.pc == 0x1000 + 30 * 0x10, "retab");
	reset(&r);                                   /* retaa */
	CHECK(step(0xD65F0BFF, &r, &fault) == 1 && r.pc == 0x1000 + 30 * 0x10, "retaa");
	reset(&r);                                   /* braa x9, x10 */
	CHECK(step(0xD71F092A, &r, &fault) == 1 && r.pc == 0x1090 && r.x[30] == 0x1000 + 30 * 0x10, "braa");
	reset(&r);                                   /* brabz x16 */
	CHECK(step(0xD61F0E1F, &r, &fault) == 1 && r.pc == 0x1100, "brabz");
	reset(&r);                                   /* blraa x9, x10 */
	CHECK(step(0xD73F092A, &r, &fault) == 1 && r.pc == 0x1090 && r.x[30] == 0x4004, "blraa");
	reset(&r);                                   /* blraaz x30: target is read before the link register is written */
	CHECK(step(0xD63F0BDF, &r, &fault) == 1 && r.pc == 0x1000 + 30 * 0x10 && r.x[30] == 0x4004, "blraaz x30");
	reset(&r); before = r;                       /* pacia x1, x2 */
	CHECK(step(0xDAC10041, &r, &fault) == 1 && r.pc == 0x4004 && r.x[1] == before.x[1], "pacia");
	reset(&r); before = r;                       /* autdzb x5 */
	CHECK(step(0xDAC13FE5, &r, &fault) == 1 && r.pc == 0x4004 && r.x[5] == before.x[5], "autdzb");
	reset(&r); before = r;                       /* xpacd x7 */
	CHECK(step(0xDAC147E7, &r, &fault) == 1 && r.pc == 0x4004 && r.x[7] == before.x[7], "xpacd");
	reset(&r); r.x[1] = 0x123456789ABCDEF0ull;   /* pacga x3, x1, x2 */
	CHECK(step(0x9AC23023, &r, &fault) == 1 && r.x[3] == 0x1234567800000000ull && r.pc == 0x4004, "pacga");
	reset(&r); before = r;                       /* pacga xzr, x1, x2 */
	CHECK(step(0x9AC2303F, &r, &fault) == 1 && r.sp == before.sp && r.pc == 0x4004, "pacga xzr");
	reset(&r); r.x[1] = MEMORY_BASE;             /* ldraa x0, [x1, #16] */
	CHECK(step(0xF8202420, &r, &fault) == 1 && r.x[0] == 0x3333 && r.x[1] == MEMORY_BASE && r.pc == 0x4004, "ldraa +16");
	reset(&r); r.x[1] = MEMORY_BASE + 24;        /* ldrab x0, [x1, #-8] */
	CHECK(step(0xF8FFF420, &r, &fault) == 1 && r.x[0] == 0x3333 && r.pc == 0x4004, "ldrab -8");
	reset(&r); r.x[1] = MEMORY_BASE;             /* ldraa x0, [x1, #8]! */
	CHECK(step(0xF8201C20, &r, &fault) == 1 && r.x[0] == 0x2222 && r.x[1] == MEMORY_BASE + 8, "ldraa writeback");
	reset(&r); r.sp = MEMORY_BASE;               /* ldraa x0, [sp, #24] */
	CHECK(step(0xF82037E0, &r, &fault) == 1 && r.x[0] == 0x4444 && r.sp == MEMORY_BASE, "ldraa sp");
	reset(&r); r.sp = MEMORY_BASE + 32;          /* ldrab x2, [sp, #-16]! */
	CHECK(step(0xF8FFEFE2, &r, &fault) == 1 && r.x[2] == 0x3333 && r.sp == MEMORY_BASE + 16, "ldrab sp writeback");
	reset(&r); r.x[1] = MEMORY_BASE + 4096;      /* ldraa x0, [x1, #-4096]: no one-word equivalent */
	{
		struct a64e_insn insn;
		a64e_decode(0xF8600420, &insn);
		CHECK(insn.kind == A64E_KIND_LDRA && insn.replacement == 0 && insn.offset == -4096, "ldraa -4096 decode");
	}
	CHECK(step(0xF8600420, &r, &fault) == 1 && r.x[0] == 0x1111, "ldraa -4096 execute");
	reset(&r); r.x[1] = 0x900000; before = r;    /* faulting load leaves the registers untouched */
	CHECK(step(0xF8202420, &r, &fault) == -1 && fault == 0x900010 && memcmp(&r, &before, sizeof(r)) == 0, "ldraa fault");
	reset(&r); r.x[1] = MEMORY_BASE;             /* ldraa xzr, [x1]: value discarded */
	before = r;
	CHECK(step(0xF820043F, &r, &fault) == 1 && r.pc == 0x4004 && r.sp == before.sp, "ldraa xzr");
	reset(&r); r.x[4] = 77;                      /* mrs x4, APIAKeyLo_EL1 */
	CHECK(step(0xD5382104, &r, &fault) == 1 && r.x[4] == 0 && r.pc == 0x4004, "mrs key");
	reset(&r); before = r;                       /* msr APGAKeyHi_EL1, x3 */
	CHECK(step(0xD5182323, &r, &fault) == 1 && r.pc == 0x4004 && r.x[3] == before.x[3], "msr key");
	reset(&r);                                   /* pacibsp never needs help */
	CHECK(step(0xD503237F, &r, &fault) == 0, "pacibsp");
	reset(&r);                                   /* eretab cannot be executed on a snapshot */
	CHECK(step(0xD69F0FFF, &r, &fault) == 0, "eretab");
	CHECK(step(0xD65F03C0, &r, &fault) == -100, "plain ret is not decoded");

	printf("a64e_execute checks failed: %d\n", failures);
	return failures ? 1 : 0;
}

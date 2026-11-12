/* SPDX-License-Identifier: MIT */
/*
 * Trap-and-emulate harness for platform/sheng/macos26/pac/a64e/a64e.h on Linux.
 *
 * The PAC test body (tests/exec/pac_exec.S built as a function) runs unmodified.
 * On a CPU without FEAT_PAuth every non-HINT PAC instruction raises SIGILL; the
 * handler below does what the XNU undefined-instruction hook is meant to do:
 *
 *   mode "emulate": execute the instruction on the saved registers
 *   mode "patch"  : overwrite the instruction with its one-word equivalent and
 *                   resume at the same PC; emulate forms that have none
 *
 * The body runs three times. In patch mode the second and third pass must not
 * trap any more. Exit status 0 means every check passed.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include "../../../platform/sheng/macos26/pac/a64e/a64e.h"

extern long pac_body(void);

static int patch_mode;
static volatile unsigned long traps_emulated;
static volatile unsigned long traps_patched;
static volatile unsigned long traps_by_kind[16];

static int
load_user(void *context, uint64_t address, uint64_t *value)
{
	(void)context;
	/* The test body only loads from mapped memory. */
	memcpy(value, (const void *)(uintptr_t)address, 8);
	return 0;
}

static void
on_sigill(int signo, siginfo_t *info, void *raw)
{
	ucontext_t *uc = raw;
	mcontext_t *mc = &uc->uc_mcontext;
	uint32_t word;
	struct a64e_insn insn;
	(void)signo;
	(void)info;

	memcpy(&word, (const void *)(uintptr_t)mc->pc, 4);
	if (!a64e_decode(word, &insn) || insn.kind == A64E_KIND_HINT || insn.kind == A64E_KIND_ERET) {
		static const char message[] = "unexpected SIGILL\n";
		(void)!write(2, message, sizeof(message) - 1);
		_exit(100);
	}
	traps_by_kind[insn.kind]++;
	if (patch_mode && insn.replacement != 0) {
		uintptr_t page = (uintptr_t)mc->pc & ~(uintptr_t)(sysconf(_SC_PAGESIZE) - 1);
		if (mprotect((void *)page, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
			_exit(101);
		}
		memcpy((void *)(uintptr_t)mc->pc, &insn.replacement, 4);
		__builtin___clear_cache((char *)(uintptr_t)mc->pc, (char *)(uintptr_t)mc->pc + 4);
		traps_patched++;
		return; /* resume at the same PC and execute the replacement */
	}
	struct a64e_regs regs;
	for (int i = 0; i < 31; i++) {
		regs.x[i] = mc->regs[i];
	}
	regs.sp = mc->sp;
	regs.pc = mc->pc;
	uint64_t fault = 0;
	if (a64e_execute(&insn, &regs, load_user, NULL, &fault) != 1) {
		_exit(102);
	}
	for (int i = 0; i < 31; i++) {
		mc->regs[i] = regs.x[i];
	}
	mc->sp = regs.sp;
	mc->pc = regs.pc;
	traps_emulated++;
}

int
main(int argc, char **argv)
{
	struct sigaction action;
	if (argc != 2 || (strcmp(argv[1], "emulate") != 0 && strcmp(argv[1], "patch") != 0 &&
	    strcmp(argv[1], "native") != 0)) {
		fprintf(stderr, "usage: %s emulate|patch|native\n", argv[0]);
		return 2;
	}
	patch_mode = strcmp(argv[1], "patch") == 0;
	if (strcmp(argv[1], "native") != 0) {
		/* One check points SP at read-only data, so signals need their own stack. */
		static char signal_stack[1 << 16];
		stack_t alternate;
		memset(&alternate, 0, sizeof(alternate));
		alternate.ss_sp = signal_stack;
		alternate.ss_size = sizeof(signal_stack);
		if (sigaltstack(&alternate, NULL) != 0) {
			return 3;
		}
		memset(&action, 0, sizeof(action));
		action.sa_sigaction = on_sigill;
		action.sa_flags = SA_SIGINFO | SA_ONSTACK;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGILL, &action, NULL) != 0) {
			return 3;
		}
	}
	for (int pass = 1; pass <= 3; pass++) {
		unsigned long before = traps_emulated + traps_patched;
		long status = pac_body();
		unsigned long traps = traps_emulated + traps_patched - before;
		printf("pass %d: status %ld, traps %lu\n", pass, status, traps);
		if (status != 0) {
			return 1;
		}
		if (patch_mode && pass > 1 && traps != 0) {
			printf("patched code still traps\n");
			return 1;
		}
	}
	printf("total: emulated %lu, patched %lu; by kind: ret %lu br %lu blr %lu strip %lu pacga %lu ldra %lu\n",
	    traps_emulated, traps_patched, traps_by_kind[A64E_KIND_RET], traps_by_kind[A64E_KIND_BR],
	    traps_by_kind[A64E_KIND_BLR], traps_by_kind[A64E_KIND_STRIP], traps_by_kind[A64E_KIND_PACGA],
	    traps_by_kind[A64E_KIND_LDRA]);
	printf("HARNESS OK\n");
	return 0;
}

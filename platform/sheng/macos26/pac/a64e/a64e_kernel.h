/* SPDX-License-Identifier: MIT */
/*
 * CPUs without pointer authentication (Cortex-A76, Cortex-A55, ...):
 * the undefined-instruction side of the fallback.
 *
 * Staged into the kernel source as osfmk/arm64/sheng_a64e_kernel.h and included
 * once by osfmk/arm64/sleh.c, in front of handle_uncategorized().
 *
 * The kernel image and its components are rewritten offline by
 * q25/tools/pac_neutralize.py, so kernel text holds no PAC instruction that can
 * trap. User space is not rewritten on disk. There a PAC instruction traps as
 * undefined, and this handler either replaces it in the resident page by its
 * one-word identity equivalent (it then traps once per page-in) or executes it
 * on the saved state when no such equivalent exists or the page must not be
 * touched.
 *
 * Boot argument sheng-a64e: 0 disables the handler, 1 only emulates,
 * 2 (default) also patches. Nothing here acts on a CPU that implements address
 * authentication, so the paths verified on such CPUs do not change.
 */
#pragma once

#include <arm64/sheng_a64e.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"

TUNABLE(uint32_t, sheng_a64e_mode, "sheng-a64e", 2);

/* Read by a debugger or by the QEMU observer; not part of any interface. */
uint64_t sheng_a64e_user_patched;
uint64_t sheng_a64e_user_emulated;
uint64_t sheng_a64e_kernel_emulated;
uint64_t sheng_a64e_kernel_last_pc;
uint32_t sheng_a64e_kernel_last_instruction;

static bool
sheng_a64e_cpu_lacks_pac(void)
{
	/* ID_AA64ISAR1_EL1: APA [7:4], API [11:8]. The loader applies the same test. */
	return (__builtin_arm_rsr64("ID_AA64ISAR1_EL1") & 0xff0ULL) == 0;
}

static int
sheng_a64e_load_user(void *context __unused, uint64_t address, uint64_t *value)
{
	return copyin((user_addr_t)address, value, sizeof(*value)) ? 1 : 0;
}

static int
sheng_a64e_load_kernel(void *context __unused, uint64_t address __unused, uint64_t *value __unused)
{
	/* The offline rewrite leaves no authenticated load in kernel text; refuse instead of guessing. */
	return 1;
}

/*
 * A user saved state is changed through the user accessors, which every kernel
 * has. The general accessors needed for a kernel saved state exist only in
 * kernels configured with DTrace; without them kernel-mode traps are left to
 * the stock handler.
 */
#if HAS_SET_SAVED_STATE_PC && HAS_SET_SAVED_STATE_LR && HAS_SET_SAVED_STATE_REG
#define SHENG_A64E_KERNEL_STATE 1
#else
#define SHENG_A64E_KERNEL_STATE 0
#endif

static uint64_t
sheng_a64e_get(arm_saved_state_t *state, unsigned reg)
{
	if (reg == 29) {
		return get_saved_state_fp(state);
	}
	if (reg == 30) {
		return get_saved_state_lr(state);
	}
	return get_saved_state_reg(state, reg);
}

static void
sheng_a64e_set(arm_saved_state_t *state, bool user, unsigned reg, uint64_t value)
{
	if (reg == 29) {
		set_saved_state_fp(state, value);
	} else if (user) {
		if (reg == 30) {
			set_user_saved_state_lr(state, value);
		} else {
			set_user_saved_state_reg(state, reg, value);
		}
	} else {
#if SHENG_A64E_KERNEL_STATE
		if (reg == 30) {
			set_saved_state_lr(state, value);
		} else {
			set_saved_state_reg(state, reg, value);
		}
#endif
	}
}

static void
sheng_a64e_set_pc(arm_saved_state_t *state, bool user, uint64_t value)
{
	if (user) {
		set_user_saved_state_pc(state, value);
	} else {
#if SHENG_A64E_KERNEL_STATE
		set_saved_state_pc(state, value);
#endif
	}
}

/* Returns true when the instruction was handled and execution can resume. */
static bool
sheng_a64e_undefined(arm_saved_state_t *state, uint32_t instr)
{
	struct a64e_insn insn;
	struct a64e_regs regs;
	uint64_t fault = 0;
	uint64_t trapped_pc;
	uint32_t cpsr;
	bool user;
	int result;

	if (sheng_a64e_mode == 0 || !is_saved_state64(state) || !a64e_decode(instr, &insn)) {
		return false;
	}
	if (insn.kind == A64E_KIND_HINT || insn.kind == A64E_KIND_ERET || !sheng_a64e_cpu_lacks_pac()) {
		return false;
	}
	cpsr = get_saved_state_cpsr(state);
	user = PSR64_IS_USER64(cpsr);
	if (!user) {
#if SHENG_A64E_KERNEL_STATE
		if (!PSR64_IS_KERNEL(cpsr)) {
			return false;
		}
#else
		return false;
#endif
	}
	if (user && (insn.kind == A64E_KIND_KEY_MSR || insn.kind == A64E_KIND_KEY_MRS)) {
		/* The key registers are not accessible from EL0 on any CPU. */
		return false;
	}
	trapped_pc = get_saved_state_pc(state);

	if (user && sheng_a64e_mode >= 2 && insn.replacement != 0 &&
	    sheng_a64e_patch_text(current_map(), (vm_map_offset_t)trapped_pc, instr, insn.replacement)) {
		/* Resume at the same PC; the replacement executes natively from now on. */
		os_atomic_inc(&sheng_a64e_user_patched, relaxed);
		return true;
	}

	for (unsigned i = 0; i < 31; i++) {
		regs.x[i] = sheng_a64e_get(state, i);
	}
	regs.sp = get_saved_state_sp(state);
	regs.pc = trapped_pc;

	result = a64e_execute(&insn, &regs, user ? sheng_a64e_load_user : sheng_a64e_load_kernel, NULL, &fault);
	if (result == 0) {
		return false;
	}
	if (result < 0) {
		if (!user) {
			return false;
		}
		mach_exception_data_type_t codes[2] = {KERN_INVALID_ADDRESS, (mach_exception_data_type_t)fault};
		exception_triage(EXC_BAD_ACCESS, codes, 2);
		__builtin_unreachable();
	}

	/* Write back only what this instruction can change. */
	switch (insn.kind) {
	case A64E_KIND_BLR:
		sheng_a64e_set(state, user, 30, regs.x[30]);
		break;
	case A64E_KIND_PACGA:
	case A64E_KIND_KEY_MRS:
		if (insn.rt != 31) {
			sheng_a64e_set(state, user, insn.rt, regs.x[insn.rt]);
		}
		break;
	case A64E_KIND_LDRA:
		if (insn.rt != 31) {
			sheng_a64e_set(state, user, insn.rt, regs.x[insn.rt]);
		}
		if (insn.writeback) {
			if (insn.rn == 31) {
				set_saved_state_sp(state, regs.sp);
			} else {
				sheng_a64e_set(state, user, insn.rn, regs.x[insn.rn]);
			}
		}
		break;
	default:
		break;
	}
	sheng_a64e_set_pc(state, user, regs.pc);

	if (user) {
		os_atomic_inc(&sheng_a64e_user_emulated, relaxed);
	} else {
		/* Kernel text that escaped the offline rewrite: keep running, but leave a trace. */
		uint64_t count = os_atomic_inc(&sheng_a64e_kernel_emulated, relaxed);
		sheng_a64e_kernel_last_pc = trapped_pc;
		sheng_a64e_kernel_last_instruction = instr;
		/* Only print where the interrupted code cannot hold a spinlock. */
		if (count <= 16 && SPSR_INTERRUPTS_ENABLED(cpsr) &&
		    current_thread() != NULL && get_preemption_level() == 0) {
			printf("SHENG: emulated kernel PAC instruction %08x at %p; rewrite this image offline\n",
			    instr, (void *)trapped_pc);
		}
	}
	return true;
}

#pragma clang diagnostic pop

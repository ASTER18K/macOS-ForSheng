/* SPDX-License-Identifier: MIT */
/*
 * Pointer authentication as the identity function, for CPUs without FEAT_PAuth.
 *
 * On such CPUs the HINT-space PAC instructions execute as NOPs and every other
 * PAC instruction is UNDEFINED. This header decodes those instructions, gives
 * the one-word identity equivalent where one exists, and can execute them on a
 * register snapshot. It is freestanding C99 without library dependencies so the
 * same code runs in the kernel exception handler and in host tests.
 *
 * Staged into the kernel source as osfmk/arm64/sheng_a64e.h. The decoder mirrors
 * q25/tools/pac_neutralize.py; q25/tests/emul compares both word by word.
 */
#ifndef SHENG_A64E_H
#define SHENG_A64E_H

#include <stdint.h>

/* Register numbers index a fixed array here; every index is checked against 31 first. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif

#define A64E_NOP    0xD503201Fu
#define A64E_RET    0xD65F03C0u
#define A64E_ERET   0xD69F03E0u

enum a64e_kind {
	A64E_KIND_NONE = 0,
	A64E_KIND_HINT,         /* HINT space: already a NOP without FEAT_PAuth */
	A64E_KIND_RET,          /* RETAA, RETAB */
	A64E_KIND_ERET,         /* ERETAA, ERETAB */
	A64E_KIND_BR,           /* BRAA, BRAB, BRAAZ, BRABZ */
	A64E_KIND_BLR,          /* BLRAA, BLRAB, BLRAAZ, BLRABZ */
	A64E_KIND_STRIP,        /* PACxx, AUTxx, XPACI, XPACD register forms */
	A64E_KIND_PACGA,
	A64E_KIND_LDRA,         /* LDRAA, LDRAB */
	A64E_KIND_KEY_MSR,      /* MSR APxxKey{Lo,Hi}_EL1, Xt */
	A64E_KIND_KEY_MRS       /* MRS Xt, APxxKey{Lo,Hi}_EL1 */
};

struct a64e_insn {
	uint8_t  kind;
	uint8_t  rn;            /* branch target, PACGA source or load base register */
	uint8_t  rt;            /* destination register */
	uint8_t  writeback;     /* LDRA only */
	int32_t  offset;        /* LDRA only, in bytes */
	uint32_t replacement;   /* one-word identity equivalent, 0 when there is none */
};

/* Returns 1 when w is a pointer authentication instruction, otherwise 0. */
static inline int
a64e_decode(uint32_t w, struct a64e_insn *out)
{
	out->kind = A64E_KIND_NONE;
	out->rn = 0;
	out->rt = 0;
	out->writeback = 0;
	out->offset = 0;
	out->replacement = 0;

	/* HINT space: 1101 0101 0000 0011 0010 CRm op2 11111 */
	if ((w & 0xFFFFF01Fu) == 0xD503201Fu) {
		uint32_t number = (w >> 5) & 0x7F;
		switch (number) {
		case 7: case 8: case 10: case 12: case 14:
		case 24: case 25: case 26: case 27: case 28: case 29: case 30: case 31:
			out->kind = A64E_KIND_HINT;
			return 1;
		default:
			return 0;
		}
	}
	if ((w & 0xFFFFFBFFu) == 0xD65F0BFFu) {
		out->kind = A64E_KIND_RET;
		out->rn = 30;
		out->replacement = A64E_RET;
		return 1;
	}
	if ((w & 0xFFFFFBFFu) == 0xD69F0BFFu) {
		out->kind = A64E_KIND_ERET;
		out->replacement = A64E_ERET;
		return 1;
	}
	if ((w & 0xFEDFF800u) == 0xD61F0800u) {
		uint32_t with_modifier = (w >> 24) & 1;
		uint32_t link = (w >> 21) & 1;
		uint32_t rn = (w >> 5) & 31;
		uint32_t rm = w & 31;
		if (!with_modifier && rm != 31) {
			return 0;
		}
		out->kind = link ? A64E_KIND_BLR : A64E_KIND_BR;
		out->rn = (uint8_t)rn;
		out->replacement = (link ? 0xD63F0000u : 0xD61F0000u) | (rn << 5);
		return 1;
	}
	if ((w & 0xFFFF0000u) == 0xDAC10000u) {
		uint32_t opcode = (w >> 10) & 0x3F;
		uint32_t rn = (w >> 5) & 31;
		if (opcode <= 7 || (opcode >= 8 && opcode <= 17 && rn == 31)) {
			out->kind = A64E_KIND_STRIP;
			out->replacement = A64E_NOP;
			return 1;
		}
		return 0;
	}
	if ((w & 0xFFE0FC00u) == 0x9AC03000u) {
		uint32_t rn = (w >> 5) & 31;
		uint32_t rd = w & 31;
		out->kind = A64E_KIND_PACGA;
		out->rn = (uint8_t)rn;
		out->rt = (uint8_t)rd;
		/* AND with Rd = 31 would write SP; the PACGA result is discarded there. */
		out->replacement = rd == 31 ? A64E_NOP : (0x92607C00u | (rn << 5) | rd);
		return 1;
	}
	if ((w & 0xFF200400u) == 0xF8200400u) {
		uint32_t sign = (w >> 22) & 1;
		uint32_t imm9 = (w >> 12) & 0x1FF;
		uint32_t writeback = (w >> 11) & 1;
		uint32_t rn = (w >> 5) & 31;
		uint32_t rt = w & 31;
		int32_t offset = (int32_t)((sign << 9) | imm9);
		if (offset & 0x200) {
			offset -= 0x400;
		}
		offset *= 8;
		out->kind = A64E_KIND_LDRA;
		out->rn = (uint8_t)rn;
		out->rt = (uint8_t)rt;
		out->writeback = (uint8_t)writeback;
		out->offset = offset;
		if (writeback) {
			if (offset >= -256 && offset <= 255) {
				out->replacement = 0xF8400C00u | (((uint32_t)offset & 0x1FF) << 12) | (rn << 5) | rt;
			}
		} else if (offset >= 0) {
			out->replacement = 0xF9400000u | (((uint32_t)offset / 8) << 10) | (rn << 5) | rt;
		} else if (offset >= -256) {
			out->replacement = 0xF8400000u | (((uint32_t)offset & 0x1FF) << 12) | (rn << 5) | rt;
		}
		return 1;
	}
	if ((w & 0xFFDFF000u) == 0xD5182000u) {
		uint32_t crm = (w >> 8) & 15;
		uint32_t op2 = (w >> 5) & 7;
		uint32_t rt = w & 31;
		int known = (crm == 1 && op2 <= 3) || (crm == 2 && op2 <= 3) || (crm == 3 && op2 <= 1);
		if (!known) {
			return 0;
		}
		out->rt = (uint8_t)rt;
		if (w & 0x00200000u) {
			out->kind = A64E_KIND_KEY_MRS;
			out->replacement = rt == 31 ? A64E_NOP : (0xD2800000u | rt);
		} else {
			out->kind = A64E_KIND_KEY_MSR;
			out->replacement = A64E_NOP;
		}
		return 1;
	}
	return 0;
}

struct a64e_regs {
	uint64_t x[31];         /* x0 .. x30 */
	uint64_t sp;
	uint64_t pc;
};

/* Reads eight bytes at address. Returns 0 on success, nonzero when the access faults. */
typedef int (*a64e_load64_fn)(void *context, uint64_t address, uint64_t *value);

/*
 * Execute one decoded instruction with identity semantics.
 * Returns  1  executed; regs holds the new state
 *          0  not executable here (HINT forms never trap, ERET needs the real instruction)
 *         -1  the load faulted; *fault_address is set and regs is unchanged
 */
static inline int
a64e_execute(const struct a64e_insn *insn, struct a64e_regs *regs,
    a64e_load64_fn load, void *context, uint64_t *fault_address)
{
	switch (insn->kind) {
	case A64E_KIND_RET:
		regs->pc = regs->x[30];
		return 1;
	case A64E_KIND_BR:
		regs->pc = insn->rn == 31 ? 0 : regs->x[insn->rn];
		return 1;
	case A64E_KIND_BLR: {
		uint64_t target = insn->rn == 31 ? 0 : regs->x[insn->rn];
		regs->x[30] = regs->pc + 4;
		regs->pc = target;
		return 1;
	}
	case A64E_KIND_STRIP:
	case A64E_KIND_KEY_MSR:
		regs->pc += 4;
		return 1;
	case A64E_KIND_KEY_MRS:
		if (insn->rt != 31) {
			regs->x[insn->rt] = 0;
		}
		regs->pc += 4;
		return 1;
	case A64E_KIND_PACGA:
		if (insn->rt != 31) {
			uint64_t source = insn->rn == 31 ? 0 : regs->x[insn->rn];
			regs->x[insn->rt] = source & 0xFFFFFFFF00000000ull;
		}
		regs->pc += 4;
		return 1;
	case A64E_KIND_LDRA: {
		uint64_t base = insn->rn == 31 ? regs->sp : regs->x[insn->rn];
		uint64_t address = base + (uint64_t)(int64_t)insn->offset;
		uint64_t value = 0;
		if (load(context, address, &value) != 0) {
			if (fault_address) {
				*fault_address = address;
			}
			return -1;
		}
		if (insn->rt != 31) {
			regs->x[insn->rt] = value;
		}
		if (insn->writeback) {
			if (insn->rn == 31) {
				regs->sp = address;
			} else {
				regs->x[insn->rn] = address;
			}
		}
		regs->pc += 4;
		return 1;
	}
	default:
		return 0;
	}
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#endif /* SHENG_A64E_H */

/* SPDX-License-Identifier: MIT */
#include "mock_common.h"
typedef int64_t mach_exception_data_type_t;
typedef int exception_type_t;
typedef unsigned int mach_msg_type_number_t;
typedef struct arm_saved_state arm_saved_state_t;
typedef struct thread *thread_t;
#define TUNABLE(type, name, key, value) static type name = value
#define os_atomic_inc(p, m) (++*(p))
#define EXC_BAD_ACCESS 1
#define DAIF_FIQF 0x40
#define SPSR_INTERRUPTS_ENABLED(x) (!(x & DAIF_FIQF))
#define PSR64_MODE_EL_MASK 0xc
#define PSR64_MODE_EL0 0
#define PSR64_MODE_RW_32 0x10
#define PSR64_IS_KERNEL(x)      ((x & PSR64_MODE_EL_MASK) > PSR64_MODE_EL0)
#define PSR64_IS_USER(x)        ((x & PSR64_MODE_EL_MASK) == PSR64_MODE_EL0)
#define PSR64_IS_USER64(x)      (PSR64_IS_USER(x) && !(x & PSR64_MODE_RW_32))
extern int copyin(const user_addr_t uaddr, void *kaddr, size_t len);
extern void exception_triage(exception_type_t exception, mach_exception_data_type_t *code, mach_msg_type_number_t codeCnt) __attribute__((noreturn));
extern vm_map_t current_map(void);
extern thread_t current_thread(void);
extern int get_preemption_level(void);
extern bool sheng_a64e_patch_text(vm_map_t map, vm_map_offset_t addr, uint32_t old_word, uint32_t new_word);
extern int is_saved_state64(const arm_saved_state_t *iss);
extern register_t get_saved_state_pc(const arm_saved_state_t *iss);
extern register_t get_saved_state_sp(const arm_saved_state_t *iss);
extern void set_saved_state_sp(arm_saved_state_t *iss, register_t sp);
extern register_t get_saved_state_lr(const arm_saved_state_t *iss);
extern register_t get_saved_state_fp(const arm_saved_state_t *iss);
extern void set_saved_state_fp(arm_saved_state_t *iss, register_t fp);
extern register_t get_saved_state_reg(const arm_saved_state_t *iss, unsigned reg);
extern uint32_t get_saved_state_cpsr(const arm_saved_state_t *iss);
extern void set_user_saved_state_pc(arm_saved_state_t *iss, register_t pc);
extern void set_user_saved_state_lr(arm_saved_state_t *iss, register_t lr);
extern void set_user_saved_state_reg(arm_saved_state_t *iss, unsigned reg, register_t value);
#ifdef MOCK_GENERAL_SETTERS
#define HAS_SET_SAVED_STATE_PC 1
#define HAS_SET_SAVED_STATE_LR 1
#define HAS_SET_SAVED_STATE_REG 1
extern void set_saved_state_pc(arm_saved_state_t *iss, register_t pc);
extern void set_saved_state_lr(arm_saved_state_t *iss, register_t lr);
extern void set_saved_state_reg(arm_saved_state_t *iss, unsigned reg, register_t value);
#endif
#include <arm64/sheng_a64e_kernel.h>
bool mock_entry(arm_saved_state_t *state, uint32_t instr);
bool mock_entry(arm_saved_state_t *state, uint32_t instr) { return sheng_a64e_undefined(state, instr); }

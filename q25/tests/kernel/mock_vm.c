/* SPDX-License-Identifier: MIT */
#include "mock_common.h"
#define PAGE_SHIFT 14
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)
#define vm_object_trunc_page(x) ((vm_object_offset_t)(x) & ~((signed)PAGE_MASK))
#define VMP_CS_ALL_FALSE 0x0
#define VMP_CS_ALL_TRUE 0xF
typedef struct vm_object *vm_object_t;
struct vm_object {
	vm_object_t shadow;
	vm_object_offset_t vo_shadow_offset;
	unsigned int phys_contiguous:1, code_signed:1;
};
#define VM_OBJECT_NULL ((vm_object_t) 0)
struct vm_page {
	unsigned int vmp_busy:1, vmp_dirty:1, vmp_wpmapped:1, vmp_error:1, vmp_cs_validated:4, vmp_cs_tainted:4;
};
typedef struct vm_page *vm_page_t;
#define VM_PAGE_NULL ((vm_page_t) 0)
struct vm_map_entry {
	vm_map_offset_t vme_start;
	unsigned int is_sub_map:1;
};
typedef struct vm_map_entry *vm_map_entry_t;
struct vm_map_lock_ctx { vm_map_entry_t vmlc_vme; vm_map_offset_t __parent_offset; bool __vmlc_locked; };
typedef struct vm_map_lock_ctx *vm_map_lock_ctx_t;
typedef vm_map_lock_ctx_t vm_map_find_lock_ctx_t;
typedef uint32_t vmrl_find_sh_flags_t;
#define VMRL_FIND_SH_DESCEND_INTO_CONSTANT 0x10u
#define VM_MAP_FIND_LOCK_CTX_DECLARE(name) \
	struct vm_map_lock_ctx private_##name = {0, 0, false}; \
	const vm_map_find_lock_ctx_t name = &private_##name
extern kern_return_t vm_map_find_entry_sh_locked(vm_map_find_lock_ctx_t vml_ctx, vm_map_t *map, vm_map_address_t addr, vmrl_find_sh_flags_t flags) __attribute__((warn_unused_result));
extern void vm_map_found_entry_sh_unlock(vm_map_find_lock_ctx_t vml_ctx, vm_map_t *map);
static inline vm_map_entry_t vm_map_found_entry_get_entry(vm_map_find_lock_ctx_t ctx) { return ctx->vmlc_vme; }
static inline vm_map_offset_t vm_map_lock_ctx_from_parent_address(vm_map_lock_ctx_t ctx, vm_map_address_t addr) { return addr - ctx->__parent_offset; }
extern vm_object_t VME_OBJECT(vm_map_entry_t entry);
extern vm_object_offset_t VME_OFFSET(vm_map_entry_t entry);
extern void vm_object_lock(vm_object_t object);
extern void vm_object_unlock(vm_object_t object);
extern vm_page_t vm_page_lookup(vm_object_t object, vm_object_offset_t offset);
extern bool vm_page_is_fictitious(const struct vm_page *m);
extern bool vm_page_is_private(const struct vm_page *m);
extern ppnum_t VM_PAGE_GET_PHYS_PAGE(const struct vm_page *m);
extern vm_offset_t phystokv(pmap_paddr_t pa);
extern bool sheng_a64e_patch_text(vm_map_t map, vm_map_offset_t addr, uint32_t old_word, uint32_t new_word);
#include <vm/sheng_a64e_vm.h>

/* SPDX-License-Identifier: MIT */
/*
 * CPUs without pointer authentication (Cortex-A76, Cortex-A55, ...):
 * the virtual-memory side of the fallback.
 *
 * Staged into the kernel source as osfmk/vm/sheng_a64e_vm.h and included once
 * by osfmk/vm/vm_map.c, behind vm_map_get_phys_page().
 *
 * A PAC instruction at addr just trapped as undefined and new_word is its
 * one-word identity equivalent. Replace it in the resident page so that it
 * does not trap again. The page is found the way vm_map_get_phys_page() finds
 * it and is modified while its object is locked, which keeps the page from
 * being freed or paged out underneath the write.
 *
 * Only pages that still hold exactly what the pager delivered are touched:
 * pages of a signed file must have passed validation and must be untainted,
 * and no page may be dirty, busy or mapped for writing. The page is left
 * clean on purpose. If it is evicted, the next page-in restores the original
 * bytes, the instruction traps again and is replaced again.
 *
 * Returns true when the word at addr now holds new_word.
 */
#pragma once

#include <arm64/proc_reg.h>
#include <arm/caches_internal.h>

bool
sheng_a64e_patch_text(
	vm_map_t                map,
	vm_map_offset_t         addr,
	uint32_t                old_word,
	uint32_t                new_word)
{
	vm_object_offset_t      offset;
	vm_object_offset_t      page_offset;
	vm_object_t             object;
	vm_map_entry_t          entry;
	bool                    patched = false;
	kern_return_t           kr;

	if (addr & 3) {
		return false;
	}

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	kr = vm_map_find_entry_sh_locked(ctx, &map, addr, VMRL_FIND_SH_DESCEND_INTO_CONSTANT);
	if (kr != KERN_SUCCESS) {
		return false;
	}
	entry = vm_map_found_entry_get_entry(ctx);
	if (entry->is_sub_map) {
		vm_map_found_entry_sh_unlock(ctx, &map);
		return false;
	}
	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL || object->phys_contiguous) {
		vm_map_found_entry_sh_unlock(ctx, &map);
		return false;
	}
	/*
	 * Shared-cache text lives in a nested map. There the entry carries the
	 * nested map's addresses, so translate addr before forming the offset.
	 * The in-page position is taken from the object offset as well, which
	 * stays correct for entries that are not aligned to the kernel page.
	 */
	offset = VME_OFFSET(entry) + (vm_map_lock_ctx_from_parent_address(ctx, addr) - entry->vme_start);
	page_offset = offset & PAGE_MASK;
	offset = vm_object_trunc_page(offset);

	vm_object_lock(object);
	while (TRUE) {
		vm_page_t page = vm_page_lookup(object, offset);
		if (page == VM_PAGE_NULL) {
			if (object->shadow) {
				vm_object_t old_object;
				vm_object_lock(object->shadow);
				old_object = object;
				offset = offset + object->vo_shadow_offset;
				object = object->shadow;
				vm_object_unlock(old_object);
				continue;
			}
			break;
		}
		if (!page->vmp_busy && !page->vmp_dirty && !page->vmp_wpmapped && !page->vmp_error &&
		    !vm_page_is_fictitious(page) && !vm_page_is_private(page) &&
		    (!object->code_signed ||
		    (page->vmp_cs_validated == VMP_CS_ALL_TRUE && page->vmp_cs_tainted == VMP_CS_ALL_FALSE))) {
			ppnum_t pn = VM_PAGE_GET_PHYS_PAGE(page);
			uint32_t *word = (uint32_t *)(phystokv((pmap_paddr_t)pn << PAGE_SHIFT) + page_offset);
			if (*word == old_word) {
				*word = new_word;
				/* Same coherence primitive as the Recovery UI page policy. */
				cache_sync_page(pn);
				patched = true;
			} else if (*word == new_word) {
				patched = true;
			}
		}
		break;
	}
	vm_object_unlock(object);
	vm_map_found_entry_sh_unlock(ctx, &map);
	return patched;
}

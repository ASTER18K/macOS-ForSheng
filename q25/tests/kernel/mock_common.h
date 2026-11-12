/* SPDX-License-Identifier: MIT */
/* Mock of the kernel declarations used by the staged headers. Signatures and
 * field names are copied from xnu-12377.121.6; only what the headers touch. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define SHENG 1
#define HAS_APPLE_PAC 1
#define __unused __attribute__((unused))
#define TRUE 1
#define FALSE 0
typedef int kern_return_t;
#define KERN_SUCCESS 0
#define KERN_INVALID_ADDRESS 1
typedef int64_t register_t; /* bsd/arm/types.h: signed on LP64 */
typedef uint64_t user_addr_t;
typedef uint64_t vm_offset_t;
typedef uint64_t vm_map_offset_t;
typedef uint64_t vm_map_address_t;
typedef unsigned long long vm_object_offset_t;
typedef uint32_t ppnum_t;
typedef uint64_t pmap_paddr_t;
typedef struct _vm_map *vm_map_t;
extern int printf(const char *, ...) __attribute__((format(printf, 1, 2)));

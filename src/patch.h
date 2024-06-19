/* Memory patching */

/* Features:
 * - Keep track of all memory patches
 * - Patch a single address at a time
 * - Undo the patches
 * - Menu display
 */

/* Design goals:
 * - Traceability: be able to see and review all patched addresses from menu
 * - Safety checking: do not patch if the memory contents is not what you expected
 * - Minimally invasive: for Digic 4 and 5, only lock down cache when there's some ROM address to patch, and unlock it when it's no longer needed
 * - Troubleshooting: automatically check whether the patch is still active or it was overwritten
 * - Unified interface: same external APIs for D45 and D78X patching, despite internal mechanism differing
 * 
 * Please do not patch memory directly; use these functions instead (especially for patches that can be undone at runtime).
 * RAM patches applied at boot time can be hardcoded for now (this may change).
 * ROM patches must be always applied via this library.
 * 
 * Long-term goal: any patch that changes Canon functionality should be applied via this library.
 * (including boot patches, state object hooks, any other hooks done by direct memory patching).
 */

#ifndef _patch_h_
#define _patch_h_

#include <stdint.h>

#define E_PATCH_OK 0
#define E_PATCH_UNKNOWN_ERROR       0x1
#define E_PATCH_ALREADY_PATCHED     0x2
#define E_PATCH_TOO_MANY_PATCHES    0x4
#define E_PATCH_OLD_VALUE_MISMATCH  0x8
#define E_PATCH_CACHE_COLLISION     0x10
#define E_PATCH_CACHE_ERROR         0x20
#define E_PATCH_REG_NOT_FOUND       0x40
#define E_PATCH_WRONG_CPU           0x80
#define E_PATCH_NO_SGI_HANDLER      0x100
#define E_PATCH_CPU1_SUSPEND_FAIL   0x200
#define E_PATCH_MMU_NOT_INIT        0x400
#define E_PATCH_BAD_MMU_PAGE        0x800
#define E_PATCH_CANNOT_MALLOC       0x1000
#define E_PATCH_MALFORMED           0x2000
#define E_PATCH_TOO_SMALL           0x4000

#define E_UNPATCH_OK                0
#define E_UNPATCH_NOT_PATCHED       0x10000
#define E_UNPATCH_OVERWRITTEN       0x20000
#define E_UNPATCH_REG_NOT_FOUND     0x80000

#undef PATCH_DEBUG

#ifdef PATCH_DEBUG
#define dbg_printf(fmt,...) { printf(fmt, ## __VA_ARGS__); }
#else
#define dbg_printf(fmt,...) {}
#endif

struct patch
{
    uint8_t *addr; // first memory address to patch (RAM or ROM)
    union
    {
        uint8_t *old_values; // pre-patch values at addr (to undo the patch)
        uint32_t old_value; // if change is small enough, store here directly
    };
    union
    {
        uint8_t *new_values; // values after patching
        uint32_t new_value; // if small enough, store here directly
    };
    uint32_t size; // number of bytes of values to patch (D45 cams can only do 4 or less per patch)
    const char *description; // displayed in the menu as help text
    uint8_t is_instruction; // D45 needs separate code paths for patching via icache or dcache,
                            // D78X do not and ignore this field.
};

// SJE TODO we're not restricted as much on number of patches
// for MMU cams, we can completely replace all content in
// multiple 64kB pages.  That said, we don't use anywhere near
// 32 in practice, so it's fine for now.  We could still make
// these limits more intelligent, probably by moving the "too much"
// logic out of patch.c and into patch_cache.c and patch_mmu.c
#define MAX_PATCHES 32
#define MAX_FUNCTION_HOOKS 32

extern int num_patches;
extern struct patch patches_global[MAX_PATCHES];

// Reads value at address, truncated according to alignment of addr.
// E.g. reads from 0x1001 return only 1 byte.
uint32_t read_value(uint8_t *addr, int is_instruction);

int is_patch_still_applied(struct patch *patch);

// Given an array of patch structs, and a count of elements in
// said array, either apply all patches or none.
// If any error is returned, no patches have been applied.
// If E_PATCH_OK is returned, all applied successfully.
//
// If count is > 1, patches are grouped into a patchset,
// which changes both display of the patches in debug menu,
// and means unpatching any of the contained patches triggers
// unpatching of all patches in the set.
int apply_patches(struct patch *patches, uint32_t count);

/* undo the patching done by apply_patches or patch_hook_function */
int unpatch_memory(uintptr_t addr);

/* 
 * Hook a custom function in the middle of some ASM code
 * similar to GDB hooks, but lighter:
 * - patches only a single address (slightly lower chances of collision)
 * - does not patch anything when the hook is triggered (self-modifying code runs only once, when set up => faster and less stuff that can break)
 * - uses less black magic (easy to understand by ASM noobs like me)
 * - hooking on instructions that do relative addressing is not fully supported; LDR Rn, [PC, #off] is fine (relocated)
 * - regs contain R0-R12 and LR (be careful)
 * - first 4 args of the inspected function are in regs[0] ... regs[3]
 * - next args are in stack[0], stack[1] and so on
 * - pc is the address where we installed the hook
 * - orig_instr is just for sanity checking
 * 
 * credits: Maqs
 */
typedef void (*patch_hook_function_cbr)(uint32_t *regs, uint32_t *stack, uint32_t pc);

int patch_hook_function(uintptr_t addr, uint32_t orig_instr, patch_hook_function_cbr hook_function, const char *description);
/* to undo, use unpatch_memory(addr) */

#if defined(CONFIG_MMU_REMAP)
#include "patch_mmu.h"
#endif // CONFIG_MMU_REMAP
#if defined(CONFIG_DIGIC_45)
#include "patch_cache.h"
#endif

#endif // _patch_h_

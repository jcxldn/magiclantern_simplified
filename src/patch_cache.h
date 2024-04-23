#ifndef _patch_cache_h_
#define _patch_cache_h_

// Don't include this header file directly, instead include patch.h.
// This header only has the parts required for patching via cache lockdown.

/* ASM code from Maqs */
/* function hooks using this struct are always paired to a simple patch (that does the jump to this code) */
union function_hook_code
{
    struct
    {
        uint32_t arm_asm[11];       /* ARM ASM code for jumping to the hook function and back */
        uint32_t reloc_insn;        /* original instruction, relocated */
        uint32_t jump_back;         /* instruction to jump back to original code */
        uint32_t addr;              /* patched address (for identification) */
        uint32_t fixup;             /* for relocating instructions that do PC-relative addressing */
        uint32_t hook_function;  /* for long call */
    };

    uint32_t code[16];
};

#define MAX_PATCHES 32
#define MAX_FUNCTION_HOOKS 32

extern int num_patches;
extern struct patch patches_global[MAX_PATCHES];
extern union function_hook_code function_hooks[MAX_FUNCTION_HOOKS];

int do_patch(uint8_t *addr, uint32_t value, int is_instruction);
int _sync_locked_caches(int also_data);
int is_patch_still_applied(int p);

#undef PATCH_DEBUG

#ifdef PATCH_DEBUG
#define dbg_printf(fmt,...) { printf(fmt, ## __VA_ARGS__); }
#else
#define dbg_printf(fmt,...) {}
#endif

#endif // _patch_cache_h_

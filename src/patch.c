/* Memory patching */

#include <dryos.h>
#include <menu.h>
#include <lvinfo.h>
#include <cache_hacks.h>
#include <patch.h>
#include <bmp.h>
#include <console.h>

// Digic 678X can't do cache lockdown, which this patching system is based on.
// Note that patch.c and cache.c both can provide sync_caches(), with patch.c
// preserving cache hacks / cache patches through a sync.  We link against both files.
// cache.c provides a weak symbol, so it will get used on D678X, but not D45.
#ifdef CONFIG_DIGIC_45

#undef PATCH_DEBUG

#ifdef PATCH_DEBUG
#define dbg_printf(fmt,...) { printf(fmt, ## __VA_ARGS__); }
#else
#define dbg_printf(fmt,...) {}
#endif

#define MAX_PATCHES 32
#define MAX_FUNCTION_HOOKS 32

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

static struct patch patches_global[MAX_PATCHES] = {{0}};
static int num_patches = 0;

/* at startup we don't have malloc, so we allocate it statically */
static union function_hook_code function_hooks[MAX_FUNCTION_HOOKS];

/**
 * Common routines
 * ===============
 */

static char last_error[70];

static void check_cache_lock_still_needed();

/* re-apply the ROM (cache) patches */
/* call this after you have flushed the caches, for example */
int _reapply_cache_patches();

/* lock or unlock the cache as needed */
static void set_cache_lock_state(int lock)
{
#ifdef CONFIG_QEMU
    return;
#endif

    if (lock)
    {
        if (!cache_locked())
        {
            printf("Locking cache\n");
            cache_lock();
        }
    }
    else
    {
        printf("Unlocking cache\n");
        cache_unlock();
    }
}

/* should be called with interrupts cleared */
int _patch_sync_caches(int also_data)
{
#ifdef CONFIG_QEMU
    return E_PATCH_OK;
#endif

    int err = 0;
    
    int locked = cache_locked();
    if (locked)
    {
        /* without this, reading from ROM right away may return the value patched in the I-Cache (5D2) */
        /* as a result, ROM patches may not be restored */
        cache_unlock();
    }

    if (also_data)
    {
        dbg_printf("Syncing caches...\n");
        _sync_caches();
    }
    else
    {
        dbg_printf("Flushing ICache...\n");
        _flush_i_cache();
    }
    
    if (locked)
    {
        cache_lock();
        err = _reapply_cache_patches();
    }
    
    return err;
}

void sync_caches()
{
    uint32_t old = cli();
    _patch_sync_caches(1);
    sei(old);
}

/* low-level routines */
uint32_t read_value(uint8_t *addr, int is_instruction)
{
#ifdef CONFIG_QEMU
    goto read_from_ram;
#endif

    uint32_t cached_value;
    
    if (is_instruction && IS_ROM_PTR(addr) && cache_locked()
        && cache_is_patchable((uint32_t)addr, TYPE_ICACHE, &cached_value) == 2)
    {
        /* return the value patched in the instruction cache */
        dbg_printf("Read from ICache: %x -> %x\n", addr, cached_value);
        return cached_value;
    }

    if (is_instruction)
    {
        /* when patching RAM instructions, the cached value might be incorrect - get it directly from RAM */
        addr = UNCACHEABLE(addr);
    }

    if (IS_ROM_PTR(addr))
    {
        dbg_printf("Read from ROM: %x -> %x\n", addr, MEM(addr));
    }

#ifdef CONFIG_QEMU
read_from_ram:
#endif
    // On ARMv5, unaligned reads via ldr succeed, but return a well defined yet unusual result.
    // The low bits of the address are masked out so it's 4-aligned, 32 bits are read,
    // then the result is rotated so the relevant low byte(s) contain the correct values.
    // E.g. if 0x11223344 is stored at address 0,
    // reading from 0x1 gets you 0x44112233,
    // reading from 0x2 gets you 0x33441122
    //
    // This means part of the returned value is from an earlier address than requested.
    // Casting the pointer type means that only the relevant low-byte(s) are returned
    // and the higher bytes are now 0.
    //
    // This means get_patch_current_value(), despite returning a u32,
    // will return an incorrect (or, at least, an incomplete) value
    // if an unaligned address is requested.
    //
    // That means patch_memory() will fail if you supply an unaligned addr
    // as the target, with a value containing anything non-zero in the high half
    // of old_value param.
    switch ((uintptr_t)addr & 3)
    {
        case 0b00:
            return *(volatile uint32_t *)addr;
        case 0b10:
            return *(volatile uint16_t *)addr;
        default:
            return *(volatile uint8_t *)addr;
    }
}

static int do_patch(uint8_t *addr, uint32_t value, int is_instruction)
{
    dbg_printf("Patching %x from %x to %x\n", addr, read_value(addr, is_instruction), value);

#ifdef CONFIG_QEMU
    goto write_to_ram;
#endif

    if (IS_ROM_PTR(addr))
    {
        /* todo: check for conflicts (@g3gg0?) */
        set_cache_lock_state(1);
        
        int cache_type = is_instruction ? TYPE_ICACHE : TYPE_DCACHE;
        if (cache_is_patchable((uint32_t)addr, cache_type, 0))
        {
            cache_fake((uint32_t)addr, value, cache_type);
            
            /* did it actually work? */
            if (read_value(addr, is_instruction) != value)
            {
                return E_PATCH_CACHE_ERROR;
            }
            
            /* yes! */
            return E_PATCH_OK;
        }
        else
        {
            return E_PATCH_CACHE_COLLISION;
        }
    }

    if (is_instruction)
    {
        /* when patching RAM instructions, bypass the data cache and write directly to RAM */
        /* (will flush the instruction cache later) */
        addr = UNCACHEABLE(addr);
    }

#ifdef CONFIG_QEMU
write_to_ram:
#endif
    // On ARMv5, unaligned writes via str succeed, but the address is rounded down
    // before use.
    //
    // This means writes to unaligned addresses will store the value at
    // a potentially unexpected location.
    //
    // The following casts mean that a potentially truncated value
    // gets stored at the expected offset.
    switch ((uintptr_t)addr & 3)
    {
        case 0b00:
            *(volatile uint32_t *)addr = value;
            break;
        case 0b10:
            *(volatile uint16_t *)addr = value;
            break;
        default:
            *(volatile uint8_t *)addr = value;
            break;
    }
    
    return E_PATCH_OK;
}

static char *error_msg(int err)
{
    static char msg[128];
    
    /* there may be one or more error flags set */
    msg[0] = 0;
    if (err & E_PATCH_UNKNOWN_ERROR)        STR_APPEND(msg, "UNKNOWN_ERROR,");
    if (err & E_PATCH_ALREADY_PATCHED)      STR_APPEND(msg, "ALREADY_PATCHED,");
    if (err & E_PATCH_TOO_MANY_PATCHES)     STR_APPEND(msg, "TOO_MANY_PATCHES,");
    if (err & E_PATCH_OLD_VALUE_MISMATCH)   STR_APPEND(msg, "OLD_VAL_MISMATCH,");
    if (err & E_PATCH_CACHE_COLLISION)      STR_APPEND(msg, "CACHE_COLLISION,");
    if (err & E_PATCH_CACHE_ERROR)          STR_APPEND(msg, "CACHE_ERROR,");
    if (err & E_PATCH_REG_NOT_FOUND)        STR_APPEND(msg, "REG_NOT_FOUND,");

    if (err & E_UNPATCH_NOT_PATCHED)        STR_APPEND(msg, "NOT_PATCHED,");
    if (err & E_UNPATCH_OVERWRITTEN)        STR_APPEND(msg, "OVERWRITTEN,");
    if (err & E_UNPATCH_REG_NOT_FOUND)      STR_APPEND(msg, "REG_NOT_FOUND,");
    
    /* remove last comma */
    int len = strlen(msg);
    if (len) msg[len-1] = 0;
    
    return msg;
}

/**
 * Simple patches
 * ==============
 */
static uint32_t get_patch_current_value(struct patch *p)
{
    return read_value(p->addr, p->is_instruction);
}

// Given an array of patch structs, and a count of elements in
// said array, either apply all patches or none.
// If any error is returned, no patches have been applied.
// If E_PATCH_OK is returned, all applied successfully.
//
// If count is > 1, patches are grouped into a patchset,
// which changes both display of the patches in debug menu,
// and means unpatching any of the contained patches triggers
// unpatching of all patches in the set.
int apply_patches(struct patch *patches, uint32_t count)
{
    int err = E_PATCH_OK;

// Ugly hack to test the change to pass in patches.
// Currently, all external code should only pass in one, 4-byte patch,
// since it hasn't been updated with patchsets in mind.
// Future work will refactor that.
if (count == 1 && patches[0].size == 4)
{
    struct patch *patch = patches;
    
    /* ensure thread safety */
    uint32_t old_int = cli();

    dbg_printf("patch_memory_work(%x)\n", patch->addr);

    /* is this address already patched? refuse to patch it twice */
    for (int i = 0; i < num_patches; i++)
    {
        if (patches_global[i].addr == patch->addr)
        {
            err = E_PATCH_ALREADY_PATCHED;
            goto end;
        }
    }

    /* do we have room for a new patch? */
    if (num_patches >= COUNT(patches_global))
    {
        err = E_PATCH_TOO_MANY_PATCHES;
        goto end;
    }

    /* fill metadata */
    patches_global[num_patches].addr = patch->addr;
    patches_global[num_patches].size = patch->size;
    patches_global[num_patches].new_value = patch->new_value;
    patches_global[num_patches].is_instruction = patch->is_instruction;
    patches_global[num_patches].description = patch->description;

    /* are we patching the right thing? */
    uint32_t old = get_patch_current_value(&patches_global[num_patches]);

    /* safety check */
    if (old != patch->old_value)
    {
        err = E_PATCH_OLD_VALUE_MISMATCH;
        goto end;
    }

    /* save backup value */
    patches_global[num_patches].old_value = old;
    
    /* checks done, backups saved, now patch */
    err = do_patch(patches_global[num_patches].addr, patch->new_value, patch->is_instruction);
    if (err) goto end;
    
    /* RAM instructions are patched in RAM (to minimize collisions and only lock down the cache when needed),
     * but we need to clear the cache and re-apply any existing ROM patches */
    if (patch->is_instruction && !IS_ROM_PTR(patch->addr))
    {
        err = _patch_sync_caches(0);
    }
    
    num_patches++;

end:
    if (err)
    {
        snprintf(last_error, sizeof(last_error), "Patch error at %x (%s)", patch->addr, error_msg(err));
        puts(last_error);
    }
    sei(old_int);
}
else {
    err = E_PATCH_TOO_MANY_PATCHES;
}
    return err;
}

static int is_patch_still_applied(int p)
{
    uint32_t current = get_patch_current_value(&patches_global[p]);
    uint32_t patched = patches_global[p].new_value;
    return (current == patched);
}

static int reapply_cache_patch(int p)
{
    uint32_t current = get_patch_current_value(&patches_global[p]);
    uint32_t patched = patches_global[p].new_value;
    
    if (current != patched)
    {
        void *addr = patches_global[p].addr;
        dbg_printf("Re-applying %x -> %x (changed to %x)\n", addr, patched, current);
        cache_fake((uint32_t) addr, patched, patches_global[p].is_instruction ? TYPE_ICACHE : TYPE_DCACHE);

        /* did it actually work? */
        if (read_value(addr, patches_global[p].is_instruction) != patched)
        {
            return E_PATCH_CACHE_ERROR;
        }
    }
    
    return E_PATCH_OK;
}

int _reapply_cache_patches()
{
#ifdef CONFIG_QEMU
    return E_PATCH_OK;
#endif

    int err = 0;
    
    /* this function is also public */
    uint32_t old_int = cli();
    
    for (int i = 0; i < num_patches; i++)
    {
        if (IS_ROM_PTR(patches_global[i].addr))
        {
            err |= reapply_cache_patch(i);
        }
    }
    
    sei(old_int);
    
    return err;
}

static void check_cache_lock_still_needed()
{
#ifdef CONFIG_QEMU
    return;
#endif

    if (!cache_locked())
    {
        return;
    }
    
    /* do we still need the cache locked? */
    int rom_patches = 0;
    for (int i = 0; i < num_patches; i++)
    {
        if (IS_ROM_PTR(patches_global[i].addr))
        {
            rom_patches = 1;
            break;
        }
    }
    
    if (!rom_patches)
    {
        /* nope, we don't */
        set_cache_lock_state(0);
    }
}

int unpatch_memory(uintptr_t _addr)
{
    uint8_t *addr = (uint8_t *)_addr;
    int err = E_UNPATCH_OK;
    uint32_t old_int = cli();

    dbg_printf("unpatch_memory(%x)\n", addr);

    /* find the patch in our data structure */
    int p = -1;
    for (int i = 0; i < num_patches; i++)
    {
        if (patches_global[i].addr == addr)
        {
            p = i;
            break;
        }
    }

    if (p == -1)
    { // patch not found
        goto end;
    }
    
    /* is the patch still applied? */
    if (!is_patch_still_applied(p))
    {
        err = E_UNPATCH_OVERWRITTEN;
        goto end;
    }

#ifndef CONFIG_QEMU
    /* not needed for ROM patches - there we will re-apply all the remaining ones from scratch */
    /* (slower, but old reverted patches should no longer give collisions) */
    if (!IS_ROM_PTR(addr))
#endif
    {
        err = do_patch(patches_global[p].addr, patches_global[p].old_value,
                       patches_global[p].is_instruction);
        if (err)
            goto end;
    }

    /* remove from our data structure (shift the other array items) */
    for (int i = p + 1; i < num_patches; i++)
    {
        patches_global[i-1] = patches_global[i];
    }
    num_patches--;

    /* also look it up in the function hooks, and zero it out if found */
    for (int i = 0; i < MAX_FUNCTION_HOOKS; i++)
    {
        if (function_hooks[i].addr == _addr)
        {
            memset(&function_hooks[i], 0, sizeof(union function_hook_code));
        }
    }

    if (IS_ROM_PTR(addr))
    {
        /* unlock and re-apply only the remaining patches */
        cache_unlock();
        cache_lock();
        err = _reapply_cache_patches();
    }
    else if (patches_global[p].is_instruction)
    {
        err = _patch_sync_caches(0);
    }

    check_cache_lock_still_needed();

end:
    if (err)
    {
        snprintf(last_error, sizeof(last_error), "Unpatch error at %x (%s)", addr, error_msg(err));
        puts(last_error);
    }
    sei(old_int);
    return err;
}

/**
 * Logging hooks
 * =============
 */
#define REG_PC      15
#define LOAD_MASK   0x0C000000
#define LOAD_INSTR  0x04000000

static uint32_t reloc_instr(uint32_t pc, uint32_t new_pc, uint32_t fixup)
{
    uint32_t instr = MEM(pc);
    uint32_t load = instr & LOAD_MASK;

    // Check for load from %pc
    if( load == LOAD_INSTR )
    {
        uint32_t reg_base   = (instr >> 16) & 0xF;
        int32_t offset      = (instr >>  0) & 0xFFF;

        if( reg_base != REG_PC )
            return instr;

        // Check direction bit and flip the sign
        if( (instr & (1<<23)) == 0 )
            offset = -offset;

        // Compute the destination, including the change in pc
        uint32_t dest       = pc + offset + 8;

        // Find the data that is being used and
        // compute a new offset so that it can be
        // accessed from the relocated space.
        uint32_t data = MEM(dest);
        int32_t new_offset = fixup - new_pc - 8;

        uint32_t new_instr = 0
            | ( 1<<23 )                 /* our fixup is always forward */
            | ( instr & ~0xFFF )        /* copy old instruction, without offset */
            | ( new_offset & 0xFFF )    /* replace offset */
            ;

        // Copy the data to the offset location
        MEM(fixup) = data;
        return new_instr;
    }
    
    return instr;
}

static int check_jump_range(uint32_t pc, uint32_t dest)
{
    /* shift offset by 2+6 bits to handle the sign bit */
    int32_t offset = (B_INSTR(pc, dest) & 0x00FFFFFF) << 8;
    
    /* compute the destination from the jump and compare to the original */
    uint32_t new_dest = ((((uint64_t)pc + 8) << 6) + offset) >> 6;
    
    if (dest != new_dest)
    {
        printf("Jump range error: %x -> %x\n", pc, dest);
        return 0;
    }
    
    return 1;
}

int patch_hook_function(uintptr_t addr, uint32_t orig_instr,
                        patch_hook_function_cbr hook_function, const char *description)
{
    int err = 0;

    /* ensure thread safety */
    uint32_t old_int = cli();
    
    /* find a free slot in function_hooks */
    int slot = -1;
    for (int i = 0; i < COUNT(function_hooks); i++)
    {
        if (function_hooks[i].addr == 0)
        {
            slot = i;
            break;
        }
    }
    
    if (slot < 0)
    {
        snprintf(last_error, sizeof(last_error), "Patch error at %x (no slot)", addr);
        puts(last_error);
        err = E_PATCH_TOO_MANY_PATCHES;
        goto end;
    }
    
    union function_hook_code *hook = &function_hooks[slot];
    
    /* check the jumps we are going to use */
    /* fixme: use long jumps? */
    if (!check_jump_range((uint32_t) &hook->reloc_insn, (uint32_t) addr + 4) ||
        !check_jump_range((uint32_t) addr,              (uint32_t) hook))
    {
        snprintf(last_error, sizeof(last_error), "Patch error at %x (jump out of range)", addr);
        puts(last_error);
        err = E_PATCH_UNKNOWN_ERROR;
        goto end;
    }
    
    /* create the hook code */
    *hook = (union function_hook_code) { .code = {
        0xe92d5fff,     /* STMFD  SP!, {R0-R12,LR}  ; save all regs to stack */
        0xe10f0000,     /* MRS    R0, CPSR          ; save CPSR (flags) */
        0xe92d0001,     /* STMFD  SP!, {R0}         ; to stack */
        0xe28d0004,     /* ADD    R0, SP, #4        ; pass them to hook function as first arg */
        0xe28d103c,     /* ADD    R1, SP, #60       ; pass stack pointer to hook function */
        0xe59f2018,     /* LDR    R2, [PC,#24]      ; pass patched address to hook function */
        0xe1a0e00f,     /* MOV    LR, PC            ; setup return address for long call */
        0xe59ff018,     /* LDR    PC, [PC,#24]      ; long call to hook_function */
        0xe8bd0001,     /* LDMFD  SP!, {R0}         ; restore CPSR */
        0xe128f000,     /* MSR    CPSR_f, R0        ; (flags only) from stack */
        0xe8bd5fff,     /* LDMFD  SP!, {R0-R12,LR}  ; restore regs */
        reloc_instr(                                
            addr,                           /*      ; relocate the original instruction */
            (uint32_t) &hook->reloc_insn,   /*      ; from the patched address */
            (uint32_t) &hook->fixup         /*      ; (it might need a fixup) */
        ),
        B_INSTR(&hook->jump_back, addr + 4),/*      ; jump back to original code */
        addr,                               /*      ; patched address (for identification) */
        hook->fixup,                        /*      ; this is updated by reloc_instr */
        (uint32_t)hook_function,
    }};

    /* since we have modified some code in RAM, sync the caches */
    sync_caches();
    
    /* patch the original instruction to jump to the hook code */
    struct patch patch =
    {
        .addr = (uint8_t *)addr,
        .old_value = orig_instr,
        .new_value = B_INSTR(addr, hook),
        .size = 4,
        .description = description,
        .is_instruction = 1
    };
    err = apply_patches(&patch, 1);
    
    if (err)
    {
        /* something went wrong? */
        memset(hook, 0, sizeof(union function_hook_code));
        goto end;
    }

end:
    sei(old_int);
    return err;
}

/**
 * GUI code
 * ========
 **/

static MENU_UPDATE_FUNC(patch_update)
{
    int p = (int) entry->priv;
    if (p < 0 || p >= num_patches)
    {
        entry->shidden = 1;
        return;
    }

    /* long description */
    MENU_SET_HELP("%s.", patches_global[p].description);

    /* short description: assume the long description is formatted as "module_name: it does this and that" */
    /* => extract module_name and display it as short description */
    char short_desc[16];
    snprintf(short_desc, sizeof(short_desc), "%s", patches_global[p].description);
    char *sep = strchr(short_desc, ':');
    if (sep) *sep = 0;
    MENU_SET_RINFO("%s", short_desc);

    /* ROM patches are considered invasive, display them with red icon */
    MENU_SET_ICON(IS_ROM_PTR(patches_global[p].addr) ? MNI_RECORD : MNI_ON, 0);

    char name[20];
    snprintf(name, sizeof(name), "%s: %X",
             patches_global[p].is_instruction ? "Code" : "Data",
             patches_global[p].addr);
    MENU_SET_NAME("%s", name);

    int val = get_patch_current_value(&patches_global[p]);
    int old_value = patches_global[p].old_value;

    /* patch value: do we have enough space to print before and after? */
    if ((val & 0xFFFF0000) == 0 && (old_value & 0xFFFF0000) == 0)
    {
        MENU_SET_VALUE("%X -> %X", old_value, val);
    }
    else
    {
        MENU_SET_VALUE("%X", val);
    }

    /* some detailed info */
    void *addr = patches_global[p].addr;
    MENU_SET_WARNING(MENU_WARN_INFO, "0x%X: 0x%X -> 0x%X.", addr, old_value, val);
    
    /* was this patch overwritten by somebody else? */
    if (!is_patch_still_applied(p))
    {
        MENU_SET_WARNING(MENU_WARN_NOT_WORKING,
            "Patch %x overwritten (expected %x, got %x).",
            patches_global[p].addr, patches_global[p].new_value,
            get_patch_current_value(&patches_global[p])
        );
    }
}

/* forward reference */
static struct menu_entry patch_menu[];

#define SIMPLE_PATCH_MENU_ENTRY(i) patch_menu[0].children[i]

static MENU_UPDATE_FUNC(patches_update)
{
    int ram_patches = 0;
    int rom_patches = 0;
    int errors = 0;

    for (int i = 0; i < MAX_PATCHES; i++)
    {
        if (i < num_patches)
        {
            if (IS_ROM_PTR(patches_global[i].addr))
            {
                rom_patches++;
            }
            else
            {
                ram_patches++;
            }
            SIMPLE_PATCH_MENU_ENTRY(i).shidden = 0;
            
            if (!is_patch_still_applied(i))
            {
                snprintf(last_error, sizeof(last_error), 
                    "Patch %x overwritten (expected %x, current value %x).",
                    patches_global[i].addr, patches_global[i].new_value,
                    get_patch_current_value(&patches_global[i])
                );
                puts(last_error);
                errors++;
            }
        }
        else
        {
            SIMPLE_PATCH_MENU_ENTRY(i).shidden = 1;
        }
    }

    if (ram_patches == 0 && rom_patches == 0)
    {
        MENU_SET_RINFO("None");
        MENU_SET_ENABLED(0);
    }
    else
    {
        MENU_SET_ICON(MNI_SUBMENU, 1);
        if (errors) MENU_SET_RINFO("%d ERR", errors);
        if (rom_patches) MENU_APPEND_RINFO("%s%d ROM", info->rinfo[0] ? ", " : "", rom_patches);
        if (ram_patches) MENU_APPEND_RINFO("%s%d RAM", info->rinfo[0] ? ", " : "", ram_patches);
    }
    
    if (last_error[0])
    {
        MENU_SET_ICON(MNI_RECORD, 0); /* red dot */
        MENU_SET_WARNING(MENU_WARN_ADVICE, last_error);
    }
    else if (cache_locked())
    {
        MENU_SET_ICON(MNI_RECORD, 0); /* red dot */
        MENU_SET_WARNING(MENU_WARN_ADVICE, "Cache is locked down (not exactly clean).");
    }
}

#define PATCH_ENTRY(i) \
        { \
            .name = "(empty)", \
            .priv = (void *)i, \
            .update = patch_update, \
            .shidden = 1, \
        }

static struct menu_entry patch_menu[] =
{
    {
        .name = "Memory patches",
        .update = patches_update,
        .select = menu_open_submenu,
        .icon_type = IT_SUBMENU,
        .help = "Show memory addresses patched in Canon code or data areas.",
        .submenu_width = 710,
        .children =  (struct menu_entry[]) {
            // for i in range(128): print "            PATCH_ENTRY(%d)," % i
            PATCH_ENTRY(0),
            PATCH_ENTRY(1),
            PATCH_ENTRY(2),
            PATCH_ENTRY(3),
            PATCH_ENTRY(4),
            PATCH_ENTRY(5),
            PATCH_ENTRY(6),
            PATCH_ENTRY(7),
            PATCH_ENTRY(8),
            PATCH_ENTRY(9),
            PATCH_ENTRY(10),
            PATCH_ENTRY(11),
            PATCH_ENTRY(12),
            PATCH_ENTRY(13),
            PATCH_ENTRY(14),
            PATCH_ENTRY(15),
            PATCH_ENTRY(16),
            PATCH_ENTRY(17),
            PATCH_ENTRY(18),
            PATCH_ENTRY(19),
            PATCH_ENTRY(20),
            PATCH_ENTRY(21),
            PATCH_ENTRY(22),
            PATCH_ENTRY(23),
            PATCH_ENTRY(24),
            PATCH_ENTRY(25),
            PATCH_ENTRY(26),
            PATCH_ENTRY(27),
            PATCH_ENTRY(28),
            PATCH_ENTRY(29),
            PATCH_ENTRY(30),
            PATCH_ENTRY(31),
            MENU_EOL,
        }
    }
};

static void patch_simple_init()
{
    menu_add("Debug", patch_menu, COUNT(patch_menu));
    patch_menu->children->parent_menu->no_name_lookup = 1;
}

INIT_FUNC("patch", patch_simple_init);

#endif

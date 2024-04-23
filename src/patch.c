/* Memory patching */

#include <dryos.h>
#include <menu.h>
#include <lvinfo.h>
#include <patch.h>
#include <bmp.h>
#include <console.h>

#if defined(CONFIG_DIGIC_45)
#include "cache_hacks.h"
#endif

// Digic 678X can't do cache lockdown, which this patching system is based on.
// Note that patch.c and cache.c both can provide sync_caches(), with patch.c
// preserving cache hacks / cache patches through a sync.  We link against both files.
// cache.c provides a weak symbol, so it will get used on D678X, but not D45.
#ifdef CONFIG_DIGIC_45

static char last_error[70];

char *error_msg(int err)
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

    /* ensure thread safety */
    uint32_t old_int = cli();
    uint32_t c = 0;
    for (; c < count; c++)
    {
        dbg_printf("patch_memory_work(%x)\n", patches[c].addr);

        // In this transitional code, fail if any patches are an unexpected size.
        // We don't handle that yet, though we will in the future.
        if (patches[c].size != 4)
        {
            err = E_PATCH_UNKNOWN_ERROR;
            goto end;
        }

        /* is this address already patched? refuse to patch it twice */
        for (int i = 0; i < num_patches; i++)
        {
            if (patches_global[i].addr == patches[c].addr)
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
        patches_global[num_patches].addr = patches[c].addr;
        patches_global[num_patches].size = patches[c].size;
        patches_global[num_patches].new_value = patches[c].new_value;
        patches_global[num_patches].is_instruction = patches[c].is_instruction;
        patches_global[num_patches].description = patches[c].description;

        /* are we patching the right thing? */
        uint32_t old = read_value(patches_global[num_patches].addr,
                                  patches_global[num_patches].is_instruction);

        /* safety check */
        if (old != patches[c].old_value)
        {
            err = E_PATCH_OLD_VALUE_MISMATCH;
            goto end;
        }

        /* save backup value */
        patches_global[num_patches].old_value = old;

        /* checks done, backups saved, now patch */
        err = do_patch(patches_global[num_patches].addr, patches[c].new_value, patches[c].is_instruction);
        if (err)
            goto end;

        /* RAM instructions are patched in RAM (to minimize collisions and only lock down the cache when needed),
         * but we need to clear the cache and re-apply any existing ROM patches */
        if (patches[c].is_instruction && !IS_ROM_PTR(patches[c].addr))
        {
#if defined(CONFIG_DIGIC_45)
            err = _sync_locked_caches(0);
#endif
        }

        num_patches++;
    }
end:
    if (err)
    {
        snprintf(last_error, sizeof(last_error), "Patch error at %x (%s)", patches[c].addr, error_msg(err));
        puts(last_error);

        // undo any prior patches, we want all or none to be applied,
        // so state is consistent.
        for (uint32_t c = 0; c < count; c++)
        {
            unpatch_memory((uint32_t)(patches[c].addr));
        }
    }
    sei(old_int);

    return err;
}

int unpatch_memory(uintptr_t _addr)
{
    // A different implementation is supplied for MMU vs non-MMU cams,
    // but we want public functions to live in patch.c, which defines
    // the interface.  Hence, a pointless looking wrapper.
    extern int _unpatch_memory(uintptr_t addr);
    return _unpatch_memory(_addr);
}

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

    int val = read_value(patches_global[p].addr, patches_global[p].is_instruction);
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
            read_value(patches_global[p].addr, patches_global[p].is_instruction)
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
                    read_value(patches_global[i].addr, patches_global[i].is_instruction)
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
#if defined(CONFIG_DIGIC_45)
// these cams have cache lockdown, D678X do not.
    else if (cache_locked())
    {
        MENU_SET_ICON(MNI_RECORD, 0); /* red dot */
        MENU_SET_WARNING(MENU_WARN_ADVICE, "Cache is locked down (not exactly clean).");
    }
#endif
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
// SJE FIXME this hard-codes 32, to match MAX_PATCHES,
// where really it should use the same constant.
// Except - MMU cams will be able to do many more patches if we want.
// Simplest to leave it as 32, we have no need for more at this time.
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

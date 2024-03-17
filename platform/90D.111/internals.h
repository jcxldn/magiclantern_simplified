/**
 * Camera internals for 90D 1.1.1
 */

// This camera has a DIGIC VIII chip
#define CONFIG_DIGIC_VIII

// REF: Commented out in 9cab5f63c5f0bee288f11988aa3ab3a923882f6c (Mar 3, 2024 | 90: Platform dir. Does not build)
#define CONFIG_MMU

// Digic 8 does not have bitmap font in ROM, try to load it from card
#define CONFIG_NO_BFNT

// has LV
#define CONFIG_LIVEVIEW

// Battery reports exact percentage
#define CONFIG_BATTERY_INFO

// enable state objects hooks
// REF: Commented out in 9cab5f63c5f0bee288f11988aa3ab3a923882f6c (Mar 3, 2024 | 90: Platform dir. Does not build)
#define CONFIG_STATE_OBJECT_HOOKS

// SRM is untested, this define is to allowing building
// without SRM_BUFFER_SIZE being found
#define CONFIG_MEMORY_SRM_NOT_WORKING

// Large total memory, leading to unusual memory mapping,
// CACHEABLE / UNCACHEABLE changes
#define CONFIG_MEM_2GB

#define CONFIG_NEW_TASK_STRUCTS
#define CONFIG_TASK_STRUCT_V2_SMP
#define CONFIG_TASK_ATTR_STRUCT_V5

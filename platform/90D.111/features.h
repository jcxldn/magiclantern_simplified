// #define CONFIG_HELLO_WORLD

#define FEATURE_VRAM_RGBA

#define FEATURE_SHOW_SHUTTER_COUNT

// working but incomplete, some allocators don't report
// anything yet as they're faked / not yet found
// JC: Triggers Err 70 when clicking on Free Memory entry
// #define FEATURE_SHOW_FREE_MEMORY

#define FEATURE_SCREENSHOT

#define FEATURE_DONT_CLICK_ME

// enable XCM only in full build
#ifndef ML_MINIMAL_OBJ
#define CONFIG_COMPOSITOR_XCM
#define CONFIG_COMPOSITOR_DEDICATED_LAYER
#define CONFIG_COMPOSITOR_XCM_V2
#endif

// mostly working - task display is too crowded.
// Maybe CPU usage should update faster?
#define CONFIG_TSKMON
#define FEATURE_SHOW_TASKS
#define FEATURE_SHOW_CPU_USAGE
#define FEATURE_SHOW_GUI_EVENTS

// enable global draw
#define FEATURE_GLOBAL_DRAW
#define FEATURE_CROPMARKS

// prevent ML attempting stack unwinding in some cases.
// This does not yet work (assumes ARM, not Thumb).  Alex recommends
// a good looking fix:
// http://www.mcternan.me.uk/ArmStackUnwinding/
#undef CONFIG_CRASH_LOG
#undef CONFIG_PROP_REQUEST_CHANGE
#undef CONFIG_ADDITIONAL_VERSION
#undef CONFIG_AUTOBACKUP_ROM

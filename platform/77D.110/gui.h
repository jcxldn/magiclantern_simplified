#ifndef _cameraspecific_gui_h_
#define _cameraspecific_gui_h_

/* Codes found for 77D 110. */

#define BGMT_WHEEL_UP                0x00
#define BGMT_WHEEL_DOWN              0x01
#define BGMT_WHEEL_LEFT              0x02
#define BGMT_WHEEL_RIGHT             0x03
#define BGMT_PRESS_SET               0x04
#define BGMT_UNPRESS_SET             0x05
#define BGMT_MENU                    0x06
#define BGMT_INFO                    0x07
//      BGMT_PRESS_DISP              0x08
//      BGMT_UNPRESS_DISP            0x09

#define BGMT_PLAY                    0x0B
//      BGMT_UNPRESS_PLAY            0x0C
#define BGMT_TRASH                   0x0D

#define BGMT_PRESS_ZOOM_IN           0x0E
#define BGMT_UNPRESS_ZOOM_IN         0x0F
#define BGMT_PRESS_ZOOM_OUT          0x10 // in dialogs
#define BGMT_UNPRESS_ZOOM_OUT        0x11

#define BGMT_Q                       0x1D
#define BGMT_LV                      0x1E

// 0x20
#define BGMT_PRESS_UP                0x2A
#define BGMT_UNPRESS_UP              0x2B
#define BGMT_PRESS_DOWN              0x2C
#define BGMT_UNPRESS_DOWN            0x2D
#define BGMT_PRESS_RIGHT             0x26
#define BGMT_UNPRESS_RIGHT           0x27
#define BGMT_PRESS_LEFT              0x28
#define BGMT_UNPRESS_LEFT            0x29

#define BGMT_PRESS_HALFSHUTTER       0x47 // same as AF-ON

// backtrace copyOlcDataToStorage call in gui_massive_event_loop
#define GMT_OLC_INFO_CHANGED         0x62

// needed for correct shutdown from powersave modes
#define GMT_GUICMD_START_AS_CHECK    0x5A
#define GMT_GUICMD_OPEN_SLOT_COVER   0x56
#define GMT_GUICMD_LOCK_OFF          0x54

/* WRONG: DNE */
    #define BGMT_PRESS_UP_RIGHT          0xF0
    #define BGMT_PRESS_UP_LEFT           0xF1
    #define BGMT_PRESS_DOWN_RIGHT        0xF2
    #define BGMT_PRESS_DOWN_LEFT         0xF3

    #define BGMT_JOY_CENTER              0xF4


    #define BGMT_UNPRESS_UDLR            0xF8

    #define BGMT_PICSTYLE                0xF9

    #define BGMT_FLASH_MOVIE             0xFA
    #define BGMT_PRESS_FLASH_MOVIE       0xFB
    #define BGMT_UNPRESS_FLASH_MOVIE     0xFC

    #define BGMT_ISO_MOVIE               0xFD
    #define BGMT_PRESS_ISO_MOVIE         0xFE
    #define BGMT_UNPRESS_ISO_MOVIE       0xFF

    /* WRONG: Not yet used */
    #define BTN_ZEBRAS_FOR_PLAYBACK      BGMT_FUNC // what button to use for zebras in Play mode
    #define BTN_ZEBRAS_FOR_PLAYBACK_NAME "FUNC"

#endif

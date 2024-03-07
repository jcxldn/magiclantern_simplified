/** \file
 * Entry points into the firmware image.
 *
 * These are the functions that we can call from our tasks
 * in the Canon 1.1.1 firmware for the EOS 90D.
 *
 */
/*
 * Copyright (C) 2018 Magic Lantern Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include <stub.h>

/** Startup **/
NSTUB(ROMBASEADDR, firmware_entry)
THUMB_FN(0xe0040104,  cstart) /* calls bzero32 and create_init_task(..., init_task, ...) (-e4 from 850D) */
THUMB_FN(0xe05cd274,  bzero32)/* zeros out a data structure */
THUMB_FN(0xe0363018,  create_init_task)   /*  low-level DryOS initialization */
THUMB_FN(0xe0040236,  init_task)  /* USER_MEM size checking, dmSetup, termDriverInit, stdlibSetup etc */
THUMB_FN(0xe05cbe80,  dcache_clean) /* loop with MCR p15 c7,c10,1; DSB  (+e4 from 850D) */
THUMB_FN(0xe05cbf54,  icache_invalidate)  /* loop with MCR p15 c7,c5,1; c7,c1,6; c7,c1,0; ISB */

/** Tasks **/
THUMB_FN(0xe064270a,  task_create) /* used to start TaskMain, GuiMainTask etc */
THUMB_FN(0xe0642922,  task_create_ex) /* as task_create, but allows selecting CPU for task */
THUMB_FN(0xe05bc4f2,  msleep) /* argument is always multiple of 10 */
DATA_PTR(0x1028,  current_task)   /* JC: untouched | from task_create; pointer to the current task structure   MFD: possibly same */
DATA_PTR(0x1010,  current_interrupt)  /* JC: untouched | from interrupt handler (VBAR + 0x18); where the interrupt ID is stored */

/** Dumper **/
THUMB_FN(0xe0222804,  dump_file)  /* tries to save a file to either "A:/%s" or "B:/%s"; calls FIO_RemoveFile/CreateFile/WriteFile/CloseFile/Flush */

/** Memory info **/
THUMB_FN(0xe018c13c,  malloc_info) /* Malloc Information */
THUMB_FN(0xe018c1d4,  sysmem_info) /* System Memory Information */
THUMB_FN(0xe017f194,  memmap_info) /* Exception vector, DRYOS system memory etc */
THUMB_FN(0xe011bbb0,  smemShowFix) /* Common Lower, Common Upper etc */

/** Everything after this until noted otherwise is at offset +0xE4 compared to 850D. **/

/** Memory allocation **/
THUMB_FN(0xe05bce58, _AllocateMemory)
THUMB_FN(0xe05bd010, _FreeMemory)
THUMB_FN(0xe05bcce2,  GetMemoryInformation)
THUMB_FN(0xe05bccb6,  GetSizeOfMaxRegion)
THUMB_FN(0xe05bc8fc, _alloc_dma_memory)
THUMB_FN(0xe05bc902, _free_dma_memory)
#THUMB_FN(0xe05bcd64,  malloc) /* int ** malloc(int **loc?,int size) */
#THUMB_FN(0xe05bceee,  free) /* void free(int block?,uint ptr?) */

/** Debug messages **/
THUMB_FN(0xe05cc4c8,  DryosDebugMsg)  /* lots of debug messages; format string is third argument */

/** DMA **/
THUMB_FN(0xe05f7486,  dma_memcpy)

/** Eventprocs (call by name) **/
THUMB_FN(0xe05b2ff2,  call)   /* many functions called by name (lv_start, lv_stop etc) */

/** File I/O **/
THUMB_FN(0xe05aec38, _FIO_OpenFile)
THUMB_FN(0xe05aecea, _FIO_CreateFile)
THUMB_FN(0xe05af0c2, _FIO_ReadFile)
THUMB_FN(0xe05af274, _FIO_WriteFile)
THUMB_FN(0xe05af1b6,  FIO_SeekSkipFile)
THUMB_FN(0xe05af490,  FIO_CloseFile)
THUMB_FN(0xe05b0516, _FIO_CreateDirectory)
//THUMB_FN(0xE04BD061,  FIO_FindFirst) // JC: to find
THUMB_FN(0xe05b0970, _FIO_FindFirstEx) // "FirstEnt"
THUMB_FN(0xe05b0a6c,  FIO_FindNextEx) // "NextEnt"

THUMB_FN(0xe05b0b2e,  FIO_FindClose) // "CloseEnt"
THUMB_FN(0xe05af62a, _FIO_GetFileSize64) // "AcqSize"

THUMB_FN(0xe05af02a, _FIO_RemoveFile)
THUMB_FN(0xe05b008e, _FIO_RenameFile)
THUMB_FN(0xe05b06fa,  FIO_Flush)   // to be called after FIO_CloseFile?
THUMB_FN(0xe05afaf4,  FIO_FInfo)
THUMB_FN(0xe05b0952,  FIO_SetErr)
THUMB_FN(0xe05b087c,  FIO_DelayFlush)
THUMB_FN(0xe05b0666,  FIO_RemDir)
THUMB_FN(0xe05b0282,  FIO_Divide)
THUMB_FN(0xe05b019a,  FIO_Concat)
THUMB_FN(0xe05aff94,  FIO_ChopT)
THUMB_FN(0xe05afea6,  FIO_ChopH)
THUMB_FN(0xe05afd14,  FIO_ChgCreateTime)
THUMB_FN(0xe05afc52,  FIO_FreeEntCnt)
THUMB_FN(0xe05afa40,  FIO_SetFTime)
THUMB_FN(0xe05af95e,  FIO_GetFTime)
THUMB_FN(0xe05af822,  FIO_SetAttr)
THUMB_FN(0xe05af550,  FIO_CloseSC)
THUMB_FN(0xe05b0db6,  FIO_Mount)
THUMB_FN(0xe05b0e48,  FIO_UnMount)
THUMB_FN(0xe05af346,  FIO_ChainW)
THUMB_FN(0xe05b05bc,  FIO_CreateDirEx)

THUMB_FN(0xe05b078e, FIO_EmgFlush)
THUMB_FN(0xe05b0930, FIO_DelayRemove) // Prints and then calls FIO_DelayFlush

/** +0xE4 Offset end. **/

/** GUI **/
//THUMB_FN(0xe05cc2c4,  GUI_Control) // JC: unsure | Looks missing on 850D, possibly same as R 
THUMB_FN(0xe059383a,  SetGUIRequestMode) // +0xBC from 850D | Code is quite different from earlier cams, not a big switch?
 // Possibly weird decomp?  Param is the same though, maybe it still works
THUMB_FN(0xe057c68c,  gui_init_end) // "EndGuiInit" | DNE on R, but does on 850D
THUMB_FN(0xe020b240,  gui_main_task) // "GUI.c"
THUMB_FN(0xe020b376,  gui_enqueue_message) // "warning! QueueLength=%d"

/** GUI timers **/
THUMB_FN(0xe05a92ce,  CancelTimer) //JC: unsure, is a loop | MFD: UPDATED WITH POSSIBLE ENTRY CODE IS A LITTLE DIFFERENT
THUMB_FN(0xe030a2fe,  SetHPTimerAfterNow) // "HPTimer.c"
THUMB_FN(0xe030a36e,  SetHPTimerNextTick) // "HPTimer.c" same "worker" function as SetHPTimerAfterNow 
THUMB_FN(0xe05a92fc,  SetTimerAfter) // "Timer1m.c"
THUMB_FN(0xe06c278a,  CancelDateTimer)

/** Interrupts **/
// JC: unsure where to look for all.
//DATA_PTR(0x4030,  pre_isr_hook)
//DATA_PTR(0x4034,  post_isr_hook)
//DATA_PTR(   0x6CC10,  isr_table_handler)
//DATA_PTR(   0x6CC14,  isr_table_param)
THUMB_FN(0xe01ab1dc,  cli_spin_lock)  /* used in AllocateMemory/FreeMemory and others */  //MFD: UPDATED WITH POSSIBLE ENTRY CODE IS A LITTLE DIFFERENT

/** MPU communication **/
// JC: prob worth someone else validating these.
THUMB_FN(0xe008ba68,  mpu_send) // "InterCom::Siodriver.c"
THUMB_FN(0xe0641f30,  mpu_recv) // JC: +0xE4 from 850D, still unsure though | "ReceiveCBR : Unknown Command" //MFD: ReceiveCBR : Unknown Command IS THERE, HOWEVER THE CODE IS QUITE DIFFERENT
DATA_PTR(0xe0641fe4,  mpu_recv_cbr) // JC: unsure | search for Direct Refs to mpu_recv address, function pointer should be found, //MFD: UPDATED WITH POSSIBLE value
// find the function that uses it, which stores it; address where stored is mpu_recv_cbr
DATA_PTR(   0x76228,  mpu_send_ring_buffer)  // ring buffer used in mpu_send
DATA_PTR( 0x2354924,  mpu_send_ring_buffer_tail) // ring buffer index incremented in mpu_send
DATA_PTR(   0x76020,  mpu_recv_ring_buffer)  // JC: unchanged | ring buffer used in SIO3_ISR, subroutine that processes two chars at a time //MFD: UPDATED WITH POSSIBLE
DATA_PTR( 0x235493c,  mpu_recv_ring_buffer_tail) // JC: unchanged | ring buffer index incremented in the above subroutine

/** Misc **/
THUMB_FN(0xe0069bf8,  vsnprintf)  /* called near dmstart; references "01234567", "0123456789", "0123456789abcdef" MFD: UPDATED WITH POSSIBLE ENTRY
 and "0123456789ABCDEF"; second arg is size; the one called by DebugMsg only knows %s */

// SJE stuff found during investigation, maybe not needed for ML
// but I wanted to call by name
THUMB_FN(0xe03dcc78,  debug_assert) // DRYOS_ASSERT_HANDLER related MFD: updated with possible entry

// SJE trying to get a substitute vsync callback working for screen refresh
// JC: untouched
//DATA_PTR(0xfd78,  winsys_sem_count)
//DATA_PTR(0xfec8,  bmp_vsync_cbr)
//THUMB_FN(0xe049e96c,  BmpVsyncCallBack)

// UNSURE or untested
//THUMB_FN(0xe00b0822,  get_task_by_id) // JC: unsure | called indirectly by task_create and functions using string "TASK Name" //MFD: updated with possible entry
THUMB_FN(0xe0397950, _get_task_info_by_id) // JC: incorrect 
NSTUB(0x0234e5c4,  dm_names) // JC: seems correct? | in DebugMsg, before the 1st loop target //MFD: updated with possible entry
NSTUB(   0x0235e09c,  sd_device) // JC: unsure | in sdReadBlk, probably 0xe02b6fa2.  Lots of refs //MFD: updated with possible entry
  // to 0x1fd7c, some to 0x1fd80

NSTUB(0x234e8ec,  gui_main_struct) // See function using "Queue Clear event" string, e020bae8
   // There's a base of struct, and some refs to fields via offsets.
   // Find the right one.
//THUMB_FN(0xe00c54ab,  GUI_ChangeMode) // JC: incorrect | "GUI_ChangeMode:%d" string
THUMB_FN(0xe05920d4,  DispSensorStart) // "guiDispSensorStart" | 0x86f4 looks to be a bool for whether Sensor is started
//THUMB_FN(0xe05920f2, DispSensorStop) JC: found this
THUMB_FN(0xe05bb824,  DeleteMemorySuite)
THUMB_FN(0xe05bbab0,  CreateMemorySuite)
THUMB_FN(0xe05bb0f6,  CreateMemoryChunk) // JC: (+0xE4 from 850D) | called from CreateMemorySuite

//NSTUB(0xe05bb7a6,  GetSizeOfMemorySuite) // not needed, but I found it along the way
THUMB_FN(0xe05cc0d4,  take_semaphore) // Same function sig and followed by give_semaphore
THUMB_FN(0xe05cc14e,  give_semaphore)
THUMB_FN(0xe05cbfd8,  create_named_semaphore) // also see df00b114, very similar, but df008418 is closer to 50D create_named_semaphore.
  // Complicated by there being df00b648, which wraps 8418 with an extra assert possible,
  // and e0426a20, which is what most sites call, which calls 8418 - but thunked.
  // In theory that means DryOS could replace the underlying create_named_semaphore
  // at run-time.  No evidence that they do.
											  //MFD: UPDATED WITH POSSIBLE VALUE

THUMB_FN(0xe04065f4,  gui_change_mode) // GUIGate_PostChangeMode
THUMB_FN(0xe04044ce,  gui_massive_event_loop) //  various "GUICMD_"* strings
//THUMB_FN(0x,  gui_init_event) // JC: ? | "-> handleGuiInit"

// The various memory functions can't be found by debug_assert strings in 850D
// because the first field to debug_assert is always 0.
// Instead, check call sites of the function, find those, find equivalent call
THUMB_FN(0xe05bb5d4,  AddMemoryChunk) // called before " 32(Src,bytes,Unit)=(%#lx,%#lx,%#lx)" in many places; see also hAddSuite
  // maybe 0xe04ba536? Similar, except it returns void, not int.
  // Also see 0xe04ba494, v. similar but diff struct offsets 
THUMB_FN(0xe05bb658,  GetFirstChunkFromSuite)
THUMB_FN(0xe05bbe78,  GetNextMemoryChunk)
THUMB_FN(0xe05bb41a,  GetMemoryAddressOfMemoryChunk)
THUMB_FN(0xe0765454,  AllocateMemoryResource) // JC: unsure, refs "RscWrap.c"
THUMB_FN(0xe0765482,  AllocateContinuousMemoryResource) // JC: same ref as above
THUMB_FN(0xe07654b0,  FreeMemoryResource) // JC: same ref as above
THUMB_FN(0xe05b2d08,  msg_queue_receive) // "SystemIF::KerQueue.c" useful for finding some of these msg_ functions


THUMB_FN(0xe05b2e66,  msg_queue_post) // used in gui_enqueue_message
THUMB_FN(0xe05b2e9c,  msg_queue_count) // Fairly hard to find.  Often used near DispLockStop, which is easy to find
   // and not used often.
THUMB_FN(0xe05b2c44,  msg_queue_create) // CreateMessageQueue - In 50D, msg_queue_create calls 0xff866424,
// the equiv of which is 0xdf00b114 (and was easier to find)
THUMB_FN(0xe05bdf8c,  prop_deliver) // used near "UNKNOWN PROPERTY ID " in call to DryosDebugMsg
THUMB_FN(0xe05bda96,  prop_register_slave)
DATA_PTR(0xeb80,  LiveViewApp_dialog) // JC: unchanged | in StartLiveViewApp()
THUMB_FN(0xe04518e8,  LiveViewApp_handler) // DebugMsg: "StartLiveViewApp(%#x)", address passed to CreateDialogBox
THUMB_FN(0xe07a3cea,  LiveViewShutterApp_handler) // DebugMsg: "StartLiveViewShutterApp", address passed to CreateDialogBox
THUMB_FN(0xe032c6c0,  PlayMovieGuideApp_handler) // "PlayMovieGuide_Start"
THUMB_FN(0xe0561bb6,  PlayMain_handler) // DebugMsg: "StartPlayMain", address passed to CreateDialogBox
THUMB_FN(0xe07053f0,  ShootOlcApp_handler) // near "StopShootOlcApp PopPalette(%d)" 
THUMB_FN(0xe08dbc18,  GetCFnData) // "GetCFnData" Function sig is different but the body looks similar.  MFD: REPLACED WITH POSSIBLE Entry
  // Looks like the inner functions use registers the outer doesn't, which confuses Ghidra
  // re how many args outer takes.
THUMB_FN(0xe08dcacc,  SetCFnData)
  // SJE size of struct has changed, don't know if this is relevant

// Not required on 200D given usage by ML is always behind cam specific guards.
//THUMB_FN(0xe069cddc,  GUI_SetLvMode) // JC: unsure, maps to func | via "GUI_SetBracketReset" - but this takes void now, and overwrites r0,
 // whereas ML thinks it takes int.  Either this is wrong, or will
 // need wrapping to preserve the reg.

THUMB_FN(0xe0757ed8, _malloc) // These two names are used in 50D and CONFIG_HELLO_WORLD won't build without them,
THUMB_FN(0xe0757f10, _free)  // however, the inital stubs for 200D call these simply malloc/free.

// On 90D, SRM_*, "hJobMemorySuite" strings don't exist
//THUMB_FN(0xe054f5c6,  SRM_AllocateMemoryResourceFor1stJob) // "hJobMemorySuite" strings, function a little earlier  //MFD: REPLACED WITH POSSIBLE Entry
//THUMB_FN(0xe05519ec,  SRM_FreeMemoryResourceFor1stJob) // find refs to "pMessage", there are several similar looking functions using it,
   // this is my best guess - this one has pPriorMessage and sets offset 8
   // in the struct to 0, offset 0x10 to param1
														 //  MDF: REPLACED WITH POSSIBLE ENTRY

THUMB_FN(0xe05be040, _prop_cleanup) // JC: incorrect, has two arguments. | "./Multicast/PropertyMgr.c" check funcs that ref this string
THUMB_FN(0xe05cb688,  CreateRecursiveLock) // JC: incorrect, takes int arg. | via "KerRLock.c", CRL() calls a function that regs this string, not many do
THUMB_FN(0xe05a955c, AcquireRecursiveLock) // JC: incorrect, two params.
THUMB_FN(0xe05a9626,  ReleaseRecursiveLock) // JC: possibly correct, sig matches
THUMB_FN(0xe059758e,  dialog_redraw) // JC: unsure | Found via checking xrefs to "pDialog->pSignature == pcSignature"  //MDF: REPLACED WITH POSSIBLE ENTRY
//THUMB_FN(0xe04b3739,  CreateResLockEntry) // JC: untouched | via xrefs to a pointer to "ResInfo"
//THUMB_FN(0xe04b3b59,  LockEngineResources) // JC: untouched | Down a bit from CreateResLockEntry, start v similar but end is different.
//THUMB_FN(0xe06217f1,  ErrForCamera_handler) // JC: untouched | ERR70, ERR80 etc (DlgErrForCamera.c, AJ_DIALOG.HANDLER_DlgErrForCamera.c)

THUMB_FN(0x0,  fsuDecodePartitionTable)

//DATA_PTR(0x40d0,  first_task) // unsure on naming here.  First item in an array of task structs.
  // Seems to always be "idle" task.
  // (we don't use this, but instead calculate it during early init,
  //  to save backporting this stub for all older cams)
NSTUB( 0x234d67c,  task_max) // JC: untouched, likely a struct. seems correct though
NSTUB(0x0235b190,  gui_task_list) // JC: untouched, incorrect | Strings have changed or been removed compared to earlier cams.  //MDF: REPLACED WITH POSSIBLE ENTRY
   // Found via checking all call sites of CreateRecursiveLock()
   // and comparing with 200d until similar code found.
   // gui_task_list is lock related
THUMB_FN(0xe083c674, _LoadCalendarFromRTC)  //JC: untouched, incorrect | MDF: REPLACED WITH POSSIBLE ENTRY
 

// These are required on Digic 678
THUMB_FN(0xe02c08ec, RefreshVrmsSurface) // "Call RefreshVrmsSurface" / "XimrExe"
DATA_PTR(   0x0235b308,  display_refresh_needed) // if 0, RefreshVrmsSurface() does nothing
THUMB_FN(0xe0194248, XimrExe) // JC: maps to func | trigger Ximr unit to execute (HW compositor, partially understood)
DATA_PTR(   0x0235b2f4,  winsys_sem)

// These are not strictly required, although recent dev work has added dependencies;
// these likely should be removed before a "real" release
THUMB_FN(0xe000be02, uart_printf)
//#NSTUB(0xdf008c7c, uart_printf) // JC: cannot find. | Thunked equivalent of the above.  Note, ARM, not Thumb.
   // Both seem to work the same.

// These are not required, but have been used for experiments, debugging, etc
THUMB_FN(0xe02bedb4, fill_rectangle_to_vram) // "FillRectangleToVram ILLEGAL_PARAMETER"
THUMB_FN(0xe02b07c3, marv_dcache_clean) // find _rgb_vram_info, this function is called with
// that address as only param, after null check.
// Function inspects the struct and does dcache_clean
// on the extent of the bitmap_data.  Not referenced
// much.  Possibly only used during init?
//THUMB_FN(0xe02ba483, JediDraw) // JC: incorrect | maybe sends a buffer to 2d accel unit, for output / render?
//THUMB_FN(0xe048f6e7, OsdReverseMode) // JC: incorrect| "OsdReverseMode" - does this flip the OSD output?
//THUMB_FN(0xe025e88d, XimrSetLayerVisibility) // JC: incorrect
//THUMB_FN(0xe025e8ad, XimrSetInputLayerMARV) // JC: incorrect
//THUMB_FN(0xe025ea65, XimrSetLayer_unk2) // JC: incorrect
//THUMB_FN(0xe025eaed, maybe_XimrSetLayerColorParams) // JC: incorrect
//THUMB_FN(0xe025e949, XimrContextInputLayerSetDimensions) // JC: incorrect
//THUMB_FN(0xe021ded9, WinSys_AllocateMemory) // JC: incorrecet
//THUMB_FN(0xe01fa5e8, WinSys_FreeMemory)


// SJE not yet sure how this one works on 850D,
// looks quite different or I'm reading it wrong
// JC: poss incorr? not validated.
#DATA_PTR(   0xfd84,  bmp_vram_info) // function e04a044c [JC: no such func on 90D] looks relevant, see refs to 0x3c0 and 0x21c; 960x540
// 0xfda0 seems bool for whether it's in 960x540 or 720x480.
// 0xfd70 looks like a struct base, at the end of this func
// you can see fd70 + 0x14, 0x18, 0x1c being used to see which vram buffer
// is active, or ready maybe.

DATA_PTR( 0x235b2bc,  _rgb_vram_info) // Used in many places, written to in "InitializeScreen"
 // At least for 200D, this is BGRA buffer, earlier in the render
 // chain than the YUV ones.  But, changes made to it will not
 // render until a refresh occurs (can manually trigger via RefreshVrmsSurface()),
 // but direct refresh via XimrExe() is simpler (we think this tells
 // the renderer peripheral to take the RGB data and update the screen(s).

NSTUB(0x0,  LCD_Palette) // Not required / changed in D8
 // FIXME - presumably we should stop using this stub in source?

DATA_PTR(0x4144,  task_dispatch_hook) // JC: Same as 850D
THUMB_FN(0xe05bda80, _prop_request_change)  //JC: ?? | MFD: REPLACED WITH POSSIBLE Entry
THUMB_FN(0xe05cc7de,  dm_set_store_level) // JC: ?? | called by "dmstore"
  // Called in init_task(), shortly before ICU Firmware version string
										  //  MFD: REPLACED WITH POSSIBLE Entry  under "[DM] Priority Escalation!!!!"
										  //  MFD: REPLACED WITH POSSIBLE Entry  under "[DM] Priority Escalation!!!!"
  // is logged.
THUMB_FN(0xe00b08dc,  task_trampoline)   //  JC: incorrect | MFD: REPLACED WITH POSSIBLE Entry


ARM32_FN(0xe00177ac,  memcpy_dryos) // useful in early contexts when we don't have
// dietlibc or newlib, and can't use stdio memcpy64 because
// that wants ML assert handling initialised.

// JC: can't find this
THUMB_FN(0xDFFE8EA0,  dcache_clean_multicore) /* loop writing to c11007b0, called after dcache_clean by copy_mmu_tables() */


#================================================================
# Anything below here is not required, but useful during dev work

THUMB_FN(0xe05ccda8,  dumpf);

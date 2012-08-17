/*
   Source for x86 emulator IdaPro plugin
   Copyright (c) 2003-2010 Chris Eagle
   
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option) 
   any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
   more details.
   
   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

/*
 *  This is the x86 Emulation plugin module
 *
 *  It is known to compile with
 *
 *  - Qt Version: Windows - Visual Studio 2008, Linux/OS X - g++
 *  - Windows only version (IDA < 6.0): Visual C++ 6.0, Visual Studio 2005, MinGW g++/make
 *
 */

#ifdef __NT__
#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>
#else
//#ifndef __NT__
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "image.h"
#endif

#ifdef PACKED
#undef PACKED
#endif

#ifndef __QT__
#include "x86emu_ui.h"
#else
#include "x86emu_ui_qt.h"
#endif

#include "x86defs.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <struct.hpp>

#include "emufuncs.h"
#include "emuheap.h"
#include "hooklist.h"
#include "break.h"
#include "emuthreads.h"
#include "peutils.h"
#include "elf32.h"
#include "emu_script.h"
#include "memmgr.h"
#include "buffer.h"

#define f_PDF 0x4444

void memoryAccessException();

#if IDA_SDK_VERSION >= 530
TForm *mainForm;
TCustomControl *stackCC;
#else
#define SEGMOD_SILENT 0
#define SEGMOD_KEEP 0
segment_t *get_first_seg(void) {
   int nseg = segs.get_next_area(0);
   return (segment_t*)segs.getn_area(nseg);
}

segment_t *get_last_seg(void) {
   int nseg = segs.get_prev_area(0xffffffff);
   return (segment_t*)segs.getn_area(nseg);
}
#endif

#ifdef __NT__
HCRYPTPROV hProv;
#else
int hProv = -1;
#endif

unsigned int randVal;

#ifndef __NT__

union FILETIME {
   unsigned long long llt;
   struct {
      dword dwLowDateTime;
      dword dwHighDateTime;
   };
};

#endif

FILETIME baseTime;

// The magic number for verifying the database blob
static const int X86EMU_BLOB_MAGIC = 0x4D363858;  // "X86M"

//The version number with which to tag the data in the
//database storage node
static const int X86EMU_BLOB_VERSION_MAJOR = 0;
static const int X86EMU_BLOB_VERSION_MINOR = 1;

//The node name to use to identify the plug-in's storage
//node in the IDA database.
static const char x86emu_node_name[] = "$ X86 CPU emulator state";
static const char kernel_node_name[] = "$ X86 kernel state";
static const char funcinfo_node_name[] = "$ X86emu FunctionInfo";
static const char petable_node_name[] = "$ X86emu PETables";
static const char module_node_name[] = "$ X86emu ModuleInfo";
static const char personality_node_name[] = "$ X86emu Personality";
static const char heap_node_name[] = "$ X86emu Heap";

//The IDA database node identifier into which the plug-in will
//store its state information when the database is saved.
netnode x86emu_node(x86emu_node_name);
netnode kernel_node(kernel_node_name);
static netnode funcinfo_node(funcinfo_node_name);
static netnode petable_node(petable_node_name);
static netnode module_node(module_node_name);
static netnode personality_node(personality_node_name);
static netnode heap_node(heap_node_name);

//will contain base address for loaded image.  Use with RVAs
IMAGE_NT_HEADERS nt;
dword peImageBase;

//set to true if saved emulator state is found
bool cpuInit = false;

//functions to create header segments and load header bytes
//from original binary into Ida database.
dword PELoadHeaders(void);
dword ELFLoadHeaders(void);

PETables pe;

//pointer to start of ELF environment strings, used to build
//envp array 
static dword elfEnvStart = 0xC0000000;
static dword elfArgStart = 0xC0000000;
static char **mainArgs;

//tracking and tracing enable
bool doTrace = false;
FILE *traceFile = NULL;
bool doTrack = false;

bool doLogLib = true;

bool idpHooked = false;
bool idbHooked = false;
bool uiHooked = false;

//Fixed for Windows XP at the moment
dword OSMajorVersion = 5;
dword OSMinorVersion = 1;
dword OSBuildNumber = 2600;

unsigned int os_personality;

extern til_t *ti;

bool isWindowCreated = false;

static int idaapi idpCallback(void * cookie, int code, va_list va);

void getRandomBytes(void *buf, unsigned int len) {
#ifdef __NT__
   if (hProv == 0) {
      CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
   }
   CryptGenRandom(hProv, len, (BYTE*)buf);
#else
   if (hProv == -1) {
      hProv = open("/dev/urandom", O_RDONLY);
   }
   read(hProv, buf, len);
#endif
}

/*
 * return system time as 64 bit quantity representing the number of 
 * 100-nanosecond intervals since January 1, 1601 (UTC).
 */
void getSystemBaseTime(dword *timeLow, dword *timeHigh) {
   *timeLow = baseTime.dwLowDateTime;
   *timeHigh = baseTime.dwHighDateTime;
}

#ifndef __NT__
void GetSystemTimeAsFileTime(FILETIME *ft) {
#if _POSIX_TIMERS > 0
   timespec ts;
   clock_gettime(CLOCK_REALTIME, &ts);
   ft->llt = ts.tv_sec;
   ft->llt *= 10000000;
   ft->llt += ts.tv_nsec / 100;
#else
   timeval tv;
   gettimeofday(&tv, NULL);
   ft->llt = tv.tv_sec;
   ft->llt *= 10000000;
   ft->llt += tv.tv_usec * 10;
#endif
}
#endif

/*
 * Add a trace entry to the trace log
 */
void traceLog(char *entry) {
   if (traceFile != NULL) {
      qfprintf(traceFile, "%s", entry);
   }
   else {
      //should never get here, but if we do just dump to message window
      msg("%s", entry);
   }
}

void setTracking(bool track) {
   doTrack = track;
}

bool getTracking() {
   return doTrack;
}

bool logLibrary() {
   return doLogLib;
}

void setLogLibrary(bool log) {
   doLogLib = log;
}

void setTracing(bool trace) {
   doTrace = trace;
}

bool getTracing() {
   return doTrace;
}

void closeTrace() {
   if (traceFile) {  //just in case a trace is already open
      qfclose(traceFile);
      traceFile = NULL;
   }
}   

void openTraceFile() {
   char buf[260];
#ifndef __QT__
   const char *filter = "All (*.*)\0*.*\0Trace files (*.trc)\0*.trc\0";
#else
   const char *filter = "All (*.*);;Trace files (*.trc)";
#endif
   char *fname = getSaveFileName("Open trace file", buf, sizeof(buf), filter);
   if (fname) {
      closeTrace();
      traceFile = qfopen(fname, "w");
   }
}

/*
 * Set the title of the emulator window according to
 * the currently running thread handle
 */
void setTitle() {
   char title[80];
   ::qsnprintf(title, sizeof(title), "x86 Emulator - thread 0x%x%s", activeThread->handle, 
           (activeThread->handle == THREAD_HANDLE_BASE) ? " (main)" : "");
   setEmulatorTitle(title);
}

//convert a control ID to a pointer to the corresponding register
unsigned int *toReg(int reg) {
   //offsets from control ID to register set array index
   static int registerMap[8] = {0, 2, -1, -1, 1, -1, 0, 0};

   if (reg < 8) {
      return &cpu.general[reg + registerMap[reg]];
   }
   return reg == 8 ? &cpu.eip : &cpu.eflags;
}

//convert a control ID to a pointer to the corresponding register
unsigned int *getRegisterPointer(int reg) {
   switch (reg) {
      case EAX: case ECX: case EDX: case EBX:
      case ESP: case EBP: case ESI: case EDI:
         return &cpu.general[reg];
      case EIP:
         return &cpu.eip;
      case EFLAGS:
         return &cpu.eflags;
      default:
         return NULL;
   }
}

//convert a control ID to a pointer to the corresponding register
unsigned int getRegisterValue(int reg) {
   unsigned int *rp = getRegisterPointer(reg);
   if (rp) {
      return *rp;
   }
   return 0;
}

void setRegisterValue(int reg, unsigned int val) {
   unsigned int *rp = getRegisterPointer(reg);
   if (rp) {
      *rp = val;
   }
}

//update all register displays from existing register values
//useful after a breakpoint or "run to"
//i.e. synchronize the display to the actual cpu/memory values
void syncDisplay() {
   for (int i = MIN_REG; i <= MAX_REG; i++) {
      updateRegisterDisplay(i);
   }

#if IDA_SDK_VERSION < 510
   // < 510 means there is not HT_IDB so we need to try to do this ourselves
   static dword lastEsp = 0;
   if (esp != lastEsp) {
      segment_t *s = get_segm_by_name(".stack");
      dword b = esp;
      dword e = lastEsp;
      if (esp > lastEsp) {
         e = esp;
         b = lastEsp;
      }
      if (b < s->startEA) {
         b = s->startEA;
      }
      if (e > s->endEA) {
         e = s->endEA;
      }
      for (dword a = b; a < e; a += 4) {
         dword val = get_long(a);
         segment_t *seg = getseg(val);
         if (seg) {
            char name[256];
            ssize_t s = get_nice_colored_name(val, name, sizeof(name), GNCN_NOCOLOR);
            if (s != 0) {
               set_cmt(a, name, false);
            }
         }
      }
      lastEsp = esp;
   }
#else
   // > 510 means there is HT_IDB and idb_hook will handle adding comments
   //whenever stack value is changed.  If also >=520, then we have opened
   //a stack display in which we can set the cursor.
#if IDA_SDK_VERSION >= 530
   segment_t *s = get_segm_by_name(".stack");
   if (s->contains(esp)) {
      //make sure stack view exists
      if (find_tform("IDA View-Stack")) {
         idaplace_t p(esp, 0);
         jumpto(stackCC, &p, 0, 0);
      }
   }
   switchto_tform(mainForm, false);
#endif
#endif
   jumpto(cpu.eip);
}

//force conversion to code at the current eip location
void forceCode() {
#if IDA_SDK_VERSION >= 540
   int len = create_insn(cpu.eip);
#else
   int len = ua_ana0(cpu.eip);
#endif
#ifdef DOUNK_EXPAND
   do_unknown_range(cpu.eip, len, DOUNK_EXPAND | DOUNK_DELNAMES);
#else
   do_unknown_range(cpu.eip, len, true);
#endif
   auto_make_code(cpu.eip); //make code at eip, or ua_code(cpu.eip);
}

//Tell IDA that the thing at the current eip location is
//code and ask it to change the display as appropriate.
void codeCheck(void) {
   ea_t loc = cpu.eip;
   ea_t head = get_item_head(loc);
   if (isUnknown(getFlags(loc))) {
      forceCode(); //or ua_code(loc);
   }
   else if (loc != head) {
      do_unknown(head, true); //undefine it
      forceCode(); //or ua_code(loc);
   }
   else if (!isCode(getFlags(loc))) {
      do_unknown(loc, true); //undefine it
      forceCode(); //or ua_code(loc);
   }
/*
   int len1 = get_item_size(loc);
#if IDA_SDK_VERSION >= 540
   int len2 = create_insn(loc);
#else
   int len2 = ua_ana0(loc);
#endif
   if (len1 != len2) {
      forceCode(); //or ua_code(loc);
   }
   else if (isUnknown(getFlags(loc))) {
      forceCode(); //or ua_code(loc);
   }
   else if (!isHead(getFlags(loc)) || !isCode(getFlags(loc))) {
//      while (!isHead(getFlags(loc))) loc--; //find start of current
      loc = get_item_head(loc);
      do_unknown(loc, true); //undefine it
      forceCode();
   }
*/
}

//update the specified register display with the specified 
//value.  useful to update register contents based on user
//input
void updateRegister(int r, dword val) {
   setRegisterValue(r, val);
   updateRegisterDisplay(r);
}

//set a register from idc.
void setIdcRegister(dword idc_reg_num, dword newVal) {
   updateRegister(idc_reg_num, newVal);
}

dword parseNumber(char *numb) {
   dword val = (dword)strtol(numb, NULL, 0); //any base
   if (val == 0x7FFFFFFF) {
      val = strtoul(numb, NULL, 0); //any base
   }
   return val;
}

//ask the user for space separated data and push it onto the 
//stack in right to left order as a C function would
void pushData() {
   int count = 0;
   char *data = inputBox("Push Stack Data", "Enter space separated data", "");
   if (data) {
      char *ptr;
      while ((ptr = strrchr(data, ' ')) != NULL) {
         *ptr++ = 0;
         if (strlen(ptr)) {
            dword val = parseNumber(ptr);
            push(val, SIZE_DWORD);
            count++;
         }
      }
      if (strlen(data)) {
         dword val = parseNumber(data);
         push(val, SIZE_DWORD);
         count++;
      }
      syncDisplay();
   }
}

//ask user for an address range and dump that address range
//to a user named file;
void dumpRange(dword low, dword hi) {
   char buf[80];
   ::qsnprintf(buf, sizeof(buf), "0x%08X-0x%08X", low, hi);
   char *range = inputBox("Enter Range", "Enter the address range to dump (inclusive)", buf);
   if (range) {
      char *end;
      dword start = strtoul(range, &end, 0);
      if (end) {
         dword finish = strtoul(++end, NULL, 0);
         char szFile[260];       // buffer for file name
#ifndef __QT__
         const char *filter = "All (*.*)\0*.*\0Binary (*.bin)\0*.BIN\0Executable (*.exe)\0*.EXE\0Dynamic link library (*.dll)\0*.DLL\0";
#else
         const char *filter = "All (*.*);;Binary (*.bin);;Executable (*.exe);;Dynamic link library (*.dll)";
#endif
         char *fname = getSaveFileName("Dump bytes to file", szFile, sizeof(szFile), filter);
         if (fname) {
            FILE *f = qfopen(szFile, "wb");
            if (f) {
               base2file(f, 0, start, finish);
/*
               for (; start <= finish; start++) {
                  unsigned char val = readByte(start);
                  qfwrite(&val, 1, 1, f);
               }
*/
               qfclose(f);
            }
         }
      }
   }
}

//ask user for an address range and dump that address range
//to a user named file;
void dumpRange() {
   dumpRange((dword)get_screen_ea(), (dword)inf.maxEA);
}

//ask user for an address range and dump that address range
//to a user named file;
void dumpEmbededPE() {
   char buf[80];
   dword base = get_screen_ea();
   if (get_word(base) != 0x5A4D) {   //check for MS-DOS magic
      showErrorMessage("Failed to locate MS-DOS magic value, canceling dump.");
      return;
   }
   dword pebase = base + get_long(base + 0x3C);
   if (get_word(pebase) != 0x4550) {   //check for PE magic
      showErrorMessage("Failed to locate PE magic value, canceling dump");
      return;
   }
   short numSections = get_word(pebase + 6);
   if (numSections < 1 || numSections > 20) {  //arbitrary range
      ::qsnprintf(buf, sizeof(buf), "Suspicious number of sections (%d), canceling dump", numSections);
      showErrorMessage(buf);
      return;
   }
   dword sectionBase = pebase + sizeof(IMAGE_NT_HEADERS);
   dword lastSection = sectionBase + (numSections - 1) * sizeof(IMAGE_SECTION_HEADER);
   dword sectionOffset = get_long(lastSection + 20);
   dword sectionSize = get_long(lastSection + 16);
   dumpRange(base, base + sectionOffset + sectionSize);
}

bool isStringPointer(char *type_str) {
   bool result = false;
   int len = strlen(type_str);
   char *buf = (char*)malloc(len + 1);
   char *p = buf;
   while (*type_str) {
      if (*type_str != ' ') {
         *p++ = *type_str;
      }
      type_str++;
   }
   *p = 0;
   if (strcmp(buf, "char*") == 0) {
      result = true;
   }
   else if (strcmp(buf, "LPCSTR") == 0) {
      result = true;
   }
   else if (strcmp(buf, "LPSTR") == 0) {
      result = true;
   }
   free(buf);
   return result;
}

void generateArgList(const char *func, argcallback_t cb, void *user) {
   char buf[256];
   int len = 8;
   FunctionInfo *f = getFunctionInfo(func);
   if (f) {
      len = f->stackItems;
   }
#if IDA_SDK_VERSION >= 520
   func_type_info_t info;
#else
   ulong arglocs[20];
   type_t *types[20];
   char *names[20];
#endif
   int haveIdaTypeInfo = f && f->type && len;
   if (haveIdaTypeInfo) {
#if IDA_SDK_VERSION >= 520  
      build_funcarg_info(ti, f->type, f->fields,
                         &info, BFI_NOCONST);
#else
      build_funcarg_arrays(f->type, f->fields, arglocs,
                           types, names, 20, true);
#endif
   }
   for (int i = 0; i < len; i++) {
      dword parm = readMem(esp + i * 4, SIZE_DWORD);
      if (haveIdaTypeInfo) {
         //change to incorporate what we know from Ida
         char type_str[128];
#if IDA_SDK_VERSION >= 520  
         print_type_to_one_line(type_str, sizeof(type_str), NULL, info[i].type.c_str());
         ::qsnprintf(buf, sizeof(buf), "arg %d: 0x%8.8x  [%s %s]", 
                  i, parm, type_str, info[i].name.c_str());
#else
         print_type_to_one_line(type_str, sizeof(type_str), NULL, types[i]);
         ::qsnprintf(buf, sizeof(buf), "arg %d: 0x%8.8x  [%s %s]", 
                  i, parm, type_str, names[i] ? names[i] : "");
#endif
         if (isStringPointer(type_str)) {
            //read string from database at address parm and append to buf
            char *val = getString(parm);
#if IDA_SDK_VERSION < 480
            int len = strlen(buf);
            ::qsnprintf(buf + len, sizeof(buf) - len, " '%s'", val); 
#else
            qstrncat(buf, " '", sizeof(buf));
            qstrncat(buf, val, sizeof(buf));
            qstrncat(buf, "'", sizeof(buf));
#endif
            free(val);
         }
      }
      else {
         ::qsnprintf(buf, sizeof(buf), "arg %d: 0x%8.8x", i, parm);
      }
      (*cb)(func, buf, i, user);
   }
#if IDA_SDK_VERSION < 520
   if (haveIdaTypeInfo) {
      free_funcarg_arrays(types, names, len);   
   }
#endif
}


/*
 * This function is used for all unemulated API functions
 */
void EmuUnemulatedCB(dword addr, const char *name) {
#ifdef DEBUG
   static char format[] = "%s called (0x%8.8x) without an emulation. Check your stack layout!";
   int len = sizeof(format) + (name ? strlen(name) : 3) + 20;
   char *mesg = (char*) qalloc(len);
   ::qsnprintf(mesg, len, format, name ? name : "???", addr);
   msg("x86emu: %s\n", mesg);
   qfree(mesg);
#endif
   restoreCursor();
   handleUnemulatedFunction(addr, name);
   shouldBreak = 1;
}

void switchThread(int tidx) {
   int idx = 0;
   for (ThreadNode *tn = threadList; tn; tn = tn->next, idx++) {
      if (idx == tidx) {
         if (tn != activeThread) {
            emu_switch_threads(tn);
            syncDisplay();
            setTitle();
         }
         msg("x86emu: Switched to thread 0x%x\n", tn->handle);
         break;
      }
   }
}

void destroyThread(int tidx) {
   int idx = 0;
   for (ThreadNode *tn = threadList; tn; tn = tn->next, idx++) {
      if (idx == tidx) {
         ThreadNode *newThread = emu_destroy_thread(tn->handle);
         if (newThread != activeThread) {
            emu_switch_threads(newThread);
            syncDisplay();
            setTitle();
         }
         break;
      }
   }   
}

//ask user for an file name and load the entire file into memory
//at the specified address
void memLoadFile(dword start) {
   char szFile[260];       // buffer for file name
   unsigned char buf[512];
   int readBytes;
   dword addr = start;
#ifndef __QT__
   const char *filter = "All (*.*)\0*.*\0";
#else
   const char *filter = "All (*.*)";
#endif
   szFile[0] = 0;
   char *fileName = getOpenFileName("Load memory from file", szFile, sizeof(szFile), filter);
   if (fileName) {
      FILE *f = qfopen(szFile, "rb");
      if (f) {
         while ((readBytes = qfread(f, buf, sizeof(buf))) > 0) {
            patch_many_bytes(addr, buf, readBytes);
            addr += readBytes;
   /*
            ptr = buf;
            for (; readBytes > 0; readBytes--) {
               writeMem(addr++, *ptr++, SIZE_BYTE);
            }
   */
         }
         qfclose(f);
      }
      msg("x86emu: Loaded 0x%X bytes from file %s to address 0x%X\n", addr - start, szFile, start);
   }
}

//skip the instruction at eip
void skip() {
   //this relies on IDA's decoding, not our own
   cpu.eip += get_item_size(cpu.eip);
   syncDisplay();
}

void grabStackBlock() {
   char msg_buf[128];
   char *bytes = inputBox("Stack space", "How many bytes of stack space?", "");
   if (bytes) {
      char *endptr;
      dword size = strtoul(bytes, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid number: %s, cancelling stack allocation", bytes);
         showErrorMessage(msg_buf);
         return;
      }
      size = (size + 3) & ~3;
      if (size) {
         esp -= size;
         ::qsnprintf(msg_buf, sizeof(msg_buf), "%d bytes allocated in the stack at 0x%08x", size, esp);
         showInformationMessage("Success", msg_buf);
         updateRegisterDisplay(ESP);
      }
      else {
         showErrorMessage("No bytes were allocated in the stack"); 
      }
   }
}

void grabHeapBlock() {
   char msg_buf[128];
   char *bytes = inputBox("Heap space", "How many bytes of heap space?", "");
   if (bytes) {
      char *endptr;
      dword size = strtoul(bytes, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid number: %s, cancelling heap allocation", bytes);
         showErrorMessage(msg_buf);
         return;
      }
      if (size) {
         dword block = HeapBase::getHeap()->calloc(size, 1);
         ::qsnprintf(msg_buf, sizeof(msg_buf), "%d bytes allocated in the heap at 0x%08x", size, block);
         showInformationMessage("Success", msg_buf);
      }
      else {
         showErrorMessage("No bytes were allocated in the heap");
      }
   }
}

void grabMmapBlock() {
   unsigned int base;
   unsigned int size;
   char msg_buf[128];
   if (getMmapBlockData(&base, &size)) {
      if (size) {
         dword rbase = base & 0xFFFFF000;
         if (base) {
            dword end = (base + size + 0xFFF) & 0xFFFFF000;
            size = end - base;
         }
         else {
            size = (size + 0xFFF) & 0xFFFFF000;
         }
         base = MemMgr::mmap(rbase, size, 0, 0);
         ::qsnprintf(msg_buf, sizeof(msg_buf), "%d bytes mmap'ed at 0x%08x", size, base);
         showInformationMessage("Success", msg_buf);
      }
      else {
         showErrorMessage("No bytes were mmap'ed");
      }
   }
}

void stepOne() {
   ThreadNode *currThread = activeThread;
   codeCheck();
   executeInstruction();
   codeCheck();
   syncDisplay();
   //may have switched threads due to thread exit
   if (currThread != activeThread) {
      setTitle();
   }
}

//use after tracing with no updates
void emuSyncDisplay() {
   codeCheck();
   syncDisplay();
}

//step the emulator one instruction without
//updating any emulator displays
void traceOne() {
   ThreadNode *currThread = activeThread;
   executeInstruction();
   //may have switched threads due to thread exit
   if (currThread != activeThread) {
      setTitle();
   }
}

//let the emulator run
//only stops when it hist a breakpoint or when 
//signaled to break
void run() {
   ThreadNode *currThread = activeThread;
   codeCheck();
   showWaitCursor();
   //tell the cpu that we want to run free
   shouldBreak = 0;
   while (!isBreakpoint(cpu.eip) && !shouldBreak) {
//                  pump(hwndDlg);
      executeInstruction();
   }
   syncDisplay();
   restoreCursor();
   //may have switched threads due to thread exit
   if (currThread != activeThread) {
      setTitle();
   }
}

void trace() {
   ThreadNode *currThread = activeThread;
   codeCheck();
   showWaitCursor();
   //tell the cpu that we want to run free
   shouldBreak = 0;
   while (!isBreakpoint(cpu.eip) && !shouldBreak) {
      executeInstruction();
   }
   restoreCursor();
   //may have switched threads due to thread exit
   if (currThread != activeThread) {
      setTitle();
   }
}

//
// Called by IDA to notify the plug-in of certain UI events.
// At the moment this is only used to catch the "saving" event
// so that the plug-in can save its state in the database.
//
static int idaapi uiCallback(void * /*cookie*/, int code, va_list /*va*/) {
   switch (code) {
   case ui_saving: {
      //
      // The user is saving the database.  Save the plug-in
      // state with it.
      //
#ifdef DEBUG
      msg(PLUGIN_NAME": ui_saving notification\n");
#endif      
      Buffer *b = new Buffer();
      x86emu_node.create(x86emu_node_name);
      if (saveState(x86emu_node) == X86EMUSAVE_OK) {
         msg("x86emu: Emulator state was saved.\n");
      }
      else {
         msg("x86emu: Emulator state save failed.\n");
      }
      delete b;
      b = new Buffer();
      funcinfo_node.create(funcinfo_node_name);
      saveFunctionInfo(*b);
      funcinfo_node.setblob(b->get_buf(), b->get_wlen(), 0, 'B');
      delete b;

      if (pe.valid) {
         b = new Buffer();
         petable_node.create(petable_node_name);
         pe.saveTables(*b);
         petable_node.setblob(b->get_buf(), b->get_wlen(), 0, 'B');
         delete b;
      }

      b = new Buffer();
      module_node.create(module_node_name);
      saveModuleData(*b);
      module_node.setblob(b->get_buf(), b->get_wlen(), 0, 'B');
      delete b;

      break;
   }
   default:
      break;
   }
   return 0;
}

#define DOS_MAGIC 0x5A4D   //"MZ"

void setPEimageBase() {
   netnode pe_node("$ PE header");
   peImageBase = pe_node.altval(0xFFFFFFFE);
   
   if (peImageBase == 0) {
      //could not find $ PE header
      segment_t *h = getnseg(0);   //peek at first segment
      dword addr = h->startEA;
      if (get_word(addr) == DOS_MAGIC) {
         peImageBase = addr;
      }
   }
}   

static void loadBaseCommon() {
   if (inf.filetype == f_PE) {
      setPEimageBase();
      //there has got to be a better way to choose til 
      //or detect what is already loaded
      init_til("mssdk.til");
   }      
   else if (inf.filetype == f_ELF) {
      //there has got to be a better way to choose til 
      //or detect what is already loaded
      init_til("gnuunx.til");
   }      
   else if (inf.filetype == f_PDF) {
      peImageBase = 0x400000;
      init_til("mssdk.til");
   }

   setUnemulatedCB(EmuUnemulatedCB);

   if (idpHooked) {
      idpHooked = false;
      unhook_from_notification_point(HT_IDP, idpCallback, NULL);
   }
}

//
// Called by IDA to notify the plug-in of certain UI events.
// At the moment this is only used to catch the "saving" event
// so that the plug-in can save its state in the database.
//
static int idaapi idpCallback(void * /*cookie*/, int code, va_list /*va*/) {
   switch (code) {
   case processor_t::newfile: {
      //
      // a new database has been opened
      //
#ifdef DEBUG
      msg(PLUGIN_NAME": newfile notification\n");
#endif  
      loadBaseCommon();
      break;
   }
   case processor_t::oldfile: {
      if (netnode_exist(module_node)) {
         // There's a module_node in the database.  Attempt to
         // instantiate the module info list from it.
         unsigned char *buf = NULL;
         size_t sz;
         msg("x86emu: Loading ModuleInfo state from existing netnode.\n");
   
         if ((buf = (unsigned char *)module_node.getblob(NULL, &sz, 0, 'B')) != NULL) {
            Buffer b(buf, sz);
            loadModuleData(b);
         }
      }
   
      //
      // See if there's a previous CPU state in this database that can
      // be used.
      //   
      if (netnode_exist(x86emu_node)) {
         //netnode should only exist if emulator was previously run
         // There's an x86emu node in the database.  Attempt to
         // instantiate the CPU state from it.
         msg("x86emu: Loading x86emu state from existing netnode.\n");
         dword loadStatus = loadState(x86emu_node);
   
         if (loadStatus == X86EMULOAD_OK) {
            cpuInit = true;
         }
         else {
            //probably shouldn't continue trying to init emulator at this point
            msg("x86emu: Error restoring x86emu state: %d.\n", loadStatus);
         }
   
         randVal = x86emu_node.altval(X86_RANDVAL);
   
         if (randVal == 0) {
            do {
               getRandomBytes(&randVal, 4);
            } while (randVal == 0);
            x86emu_node.altset(X86_RANDVAL, randVal);
         }
   
         baseTime.dwLowDateTime = x86emu_node.altval(SYSTEM_TIME_LOW);
         baseTime.dwHighDateTime = x86emu_node.altval(SYSTEM_TIME_HIGH);
         
         os_personality = x86emu_node.altval(OS_PERSONALITY);
      }
      else {
         msg("x86emu: No saved x86emu state data was found.\n");
      }
      if (netnode_exist(heap_node)) {
         // There's a heap_node in the database.  Attempt to
         // instantiate the heap info from it.
         unsigned char *buf = NULL;
         size_t sz;
         msg("x86emu: Loading HeapInfo state from existing netnode.\n");
         Buffer *b = NULL;
         if ((buf = (unsigned char *)heap_node.getblob(NULL, &sz, 0, 'B')) != NULL) {
            b = new Buffer(buf, sz);
         }
         unsigned int heap = x86emu_node.altval(HEAP_PERSONALITY);
         switch (heap) {
            case RTL_HEAP:
               break;
            case PHKMALLOC_HEAP:
               break;
            case JEMALLOC_HEAP:
               break;
            case DLMALLOC_2_7_2_HEAP:
               break;
            case LEGACY_HEAP:
            default:
               if (b) {
                  EmuHeap::loadHeapLayout(*b);
               }
               break;
         }
         delete b;
      }
      if (netnode_exist(funcinfo_node)) {
         // There's a funcinfo_node in the database.  Attempt to
         // instantiate the function info list from it.
         unsigned char *buf = NULL;
         size_t sz;
         msg("x86emu: Loading FunctionInfo state from existing netnode.\n");
   
         if ((buf = (unsigned char *)funcinfo_node.getblob(NULL, &sz, 0, 'B')) != NULL) {
            Buffer b(buf, sz);
            loadFunctionInfo(b);
         }
      }
      if (netnode_exist(petable_node)) {
         // There's a petable_node in the database.  Attempt to
         // instantiate the petable info list from it.
         unsigned char *buf = NULL;
         size_t sz;
         msg("x86emu: Loading PETable state from existing netnode.\n");
   
         if ((buf = (unsigned char *)petable_node.getblob(NULL, &sz, 0, 'B')) != NULL) {
            Buffer b(buf, sz);
            pe.loadTables(b);
         }
         if (!pe.valid) {
            petable_node.kill();
         }  
      }
      
      loadBaseCommon();
      break;
   }
   default:
      break;
   }
   return 0;
}

void dumpHeap() {
   const MallocNode *n = HeapBase::getHeap()->heapHead();
   msg("x86emu: Heap Status ---\n");
   while (n) {
      unsigned int sz = n->getSize();
      unsigned int base = n->getBase();
      msg("   0x%x-0x%x (0x%x bytes)\n", base, base + sz - 1, sz); 
      n = n->nextNode();
   }
}

void doReset() {
   resetCpu();
   cpu.eip = get_screen_ea();
   syncDisplay();
}

void jumpToCursor() {
   cpu.eip = get_screen_ea();
   syncDisplay();
}

void runToCursor() {
   ThreadNode *currThread = activeThread;
   codeCheck();
   showWaitCursor();
   dword endAddr = get_screen_ea();
   //tell the cpu that we want to run free
   shouldBreak = 0;
   while (cpu.eip != endAddr && !shouldBreak) {
      executeInstruction();
   }
   syncDisplay();
   restoreCursor();
   codeCheck();
   //may have switched threads due to thread exit
   if (currThread != activeThread) {
      setTitle();
   }
}

void tagImportAddressSavePoint() {
   char loc[16];
   ::qsnprintf(loc, sizeof(loc), "0x%08X", (dword)get_screen_ea());
   char *addr = inputBox("Import Address Save Point", "Specify location of import address save", loc);
   if (addr) {
      importSavePoint = strtoul(addr, NULL, 0);
//    sscanf(value, "%X", &importSavePoint);
   }
}

void setBreakpoint() {
   char loc[16];
   ::qsnprintf(loc, sizeof(loc), "0x%08X", (dword)get_screen_ea());
   char *bpt = inputBox("Set Breakpoint", "Specify breakpoint location", loc);
   if (bpt) {
      dword bp = strtoul(bpt, NULL, 0);
//                  sscanf(value, "%X", &bp);                
      addBreakpoint(bp);
   }
}

void clearBreakpoint() {
   char loc[16];
   ::qsnprintf(loc, sizeof(loc), "0x%08X", (dword)get_screen_ea());
   char *bpt = inputBox("Remove Breakpoint", "Specify breakpoint location", loc);
   if (bpt) {
//                  sscanf(value, "%X", &bp);
      dword bp = strtoul(bpt, NULL, 0);
      removeBreakpoint(bp);
   }
}

void generateMemoryException() {
   cpu.initial_eip = cpu.eip;  //since we are not going through executeInstruction
   memoryAccessException();
   syncDisplay();
}

void doExportLookup() {
   char loc[16];
   ::qsnprintf(loc, sizeof(loc), "0x%08X", eax);
   char *addr = inputBox("Export Lookup", "Specify export address", loc);
   if (addr) {
//                  sscanf(value, "%X", &export_addr);
      dword export_addr = strtoul(addr, NULL, 0);
      char *exp = reverseLookupExport(export_addr);
      if (exp) {
//                     msg("x86emu: reverseLookupExport: %s\n", exp);
         int len = 20 + strlen(exp);
         char *mesg = (char*)qalloc(len);
         ::qsnprintf(mesg, len, "0x%08X: %s", export_addr, exp);
         showInformationMessage("Export Lookup", mesg);
         qfree(mesg);
      }
      else {
//                     msg("x86emu: reverseLookupExport failed\n");
         showInformationMessage("Export Lookup", "No name found");
      }
   }
}

FILE *LoadHeadersCommon(dword addr, segment_t &s, bool createSeg = true) {
   char buf[260];
#if (IDA_SDK_VERSION < 490)
   char *fname = get_input_file_path();
   FILE *f = fopen(fname, "rb");
#else
   get_input_file_path(buf, sizeof(buf));
   FILE *f = fopen(buf, "rb");
#endif
   if (f == NULL) {
      showErrorMessage("Original input file not found.");
#ifndef __QT__
      const char *filter = "All (*.*)\0*.*\0Executable files (*.exe; *.dll)\0*.EXE;*.DLL\0";
#else
      const char *filter = "All (*.*);;Executable files (*.exe; *.dll)";
#endif
      buf[0] = 0;
      char *fname = getOpenFileName("Select input file", buf, sizeof(buf), filter);
      if (fname) {
         f = fopen(buf, "rb");
      }
   }
   if (f && createSeg) {
      //create the new segment
      memset(&s, 0, sizeof(s));
      s.startEA = addr;
      s.endEA = BADADDR;
      s.align = saRelPara;
      s.comb = scPub;
      s.perm = SEGPERM_WRITE | SEGPERM_READ;
      s.bitness = 1;
      s.type = SEG_DATA;
      s.color = DEFCOLOR;
      if (add_segm_ex(&s, ".headers", "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
         //zero out the newly created segment
         for (ea_t ea = s.startEA; ea < s.endEA; ea++) {
            patch_byte(ea, 0);
         }
      }
   }
   else {
      //just can't open input binary!
   }
   return f;
}

void loadResources(FILE *f) {
   IMAGE_SECTION_HEADER *sh = (IMAGE_SECTION_HEADER*)pe.sections;
   for (int i = 0; i < pe.num_sections; i++) {
      if (strcmp((char*)sh[i].Name, ".rsrc") == 0) {
         dword rsrcBase = pe.base + sh[i].VirtualAddress;
         segment_t *r = getseg(rsrcBase);
         if (r == NULL) {   //nothing loaded at rsrcBase address
            if (fseek(f, sh[i].PointerToRawData, SEEK_SET) == 0) {
               unsigned int sz = sh[i].SizeOfRawData;
               unsigned char *rsrc = (unsigned char*)malloc(sz);
               if (fread(rsrc, sz, 1, f) != 1)  {
                  free(rsrc);
                  return;
               }
               createSegment(rsrcBase, sh[i].Misc.VirtualSize, rsrc, sz, ".rsrc");
               free(rsrc);
            }
         }
      }
   }
}

dword PELoadHeaders() {
   dword addr = 0;
      
   if (peImageBase == 0) {
      int nsegs = get_segm_qty();
      //loop through segs looking for MZ
      for (int i = 0; i < nsegs; i++) {
         segment_t *h = getnseg(i);
         if (get_word(h->startEA) == DOS_MAGIC) {
            addr = h->startEA;
//            msg("peImageBase missing, trying %x\n", addr);
            break;
         }
      }
   }
   else {
      addr = peImageBase;
   }
#ifdef DEBUG
   msg(PLUGIN_NAME": peImageBase set to 0x%08x\n", peImageBase);
#endif      
   segment_t s;
   if (get_word(addr) == DOS_MAGIC) {
      peImageBase = addr;
      //header is already present
//      msg("PE header already present\n");
      if (netnode_exist(petable_node)) {
         return addr;
      }
//      msg("petable_node does not exist yet\n");

      IMAGE_NT_HEADERS nt;
      dword pe_offset = get_long(addr + 0x3C);

      get_many_bytes(addr + pe_offset, &nt, sizeof(nt));

      IMAGE_SECTION_HEADER *sect = new IMAGE_SECTION_HEADER[nt.FileHeader.NumberOfSections];
      get_many_bytes(addr + pe_offset + sizeof(nt), sect, sizeof(IMAGE_SECTION_HEADER) * nt.FileHeader.NumberOfSections);

      pe.setBase(nt.OptionalHeader.ImageBase);
      pe.setNtHeaders(&nt);
      pe.setSectionHeaders(nt.FileHeader.NumberOfSections, sect);

      applyPEHeaderTemplates(addr);

      delete [] sect;

      FILE *f = LoadHeadersCommon(addr & 0xFFFF0000, s, false);
      if (f) {
         pe.buildThunks(f);
         loadResources(f);
         fclose(f);
      }
      return addr;
   }
   else {
      FILE *f = LoadHeadersCommon(addr & 0xFFFF0000, s);
      if (f) {
//         msg("Reading PE headers from exe file\n");
         IMAGE_DOS_HEADER *dos;
         IMAGE_NT_HEADERS *nt;
         IMAGE_SECTION_HEADER *sect;
         addr = s.startEA;
         dword need = s.endEA - addr;
   
         byte *buf = (byte*)malloc(need);
         fread(buf, 1, need, f);
         dos = (IMAGE_DOS_HEADER*)buf;

         nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
         sect = (IMAGE_SECTION_HEADER*)(nt + 1);
   
         pe.setBase(nt->OptionalHeader.ImageBase);
         pe.setNtHeaders(nt);
         pe.setSectionHeaders(nt->FileHeader.NumberOfSections, sect);
   
         need = sect[0].PointerToRawData;
         patch_many_bytes(s.startEA, buf, nt->OptionalHeader.SizeOfHeaders);
   
         applyPEHeaderTemplates(addr);
   
         free(buf);
   
         pe.buildThunks(f);
         loadResources(f);
         fclose(f);
         return addr;
      }
   }
   return 0xFFFFFFFF;
}

#define ELF_MAGIC 0x464C457F  //"\x7FELF"

dword ELFLoadHeaders() {
   segment_t s;
   dword addr = inf.minEA;
   if (get_long(addr) == ELF_MAGIC) {
      //header is already present
      return addr;
   }
   dword base_addr = addr & 0xFFFFF000;
   if (addr == base_addr) {
      base_addr -= 0x1000;
   }
   msg("%x %x\n", addr, base_addr);
   FILE *f = LoadHeadersCommon(base_addr, s);
   if (f) {
      Elf32_Ehdr *elf;
      Elf32_Phdr *phdr;
      addr = s.startEA;
      dword need = s.endEA - addr;

#if (IDA_SDK_VERSION < 520)
      tid_t elf_hdr = til2idb(-1, "Elf32_Ehdr");
      tid_t elf_phdr = til2idb(-1, "Elf32_Phdr");
#else
      tid_t elf_hdr = import_type(ti, -1, "Elf32_Ehdr");
      tid_t elf_phdr = import_type(ti, -1, "Elf32_Phdr");
#endif

      byte *buf = (byte*)malloc(need);
      fread(buf, 1, need, f);
      elf = (Elf32_Ehdr*)buf;
      phdr = (Elf32_Phdr*)(buf + elf->e_phoff);

      if (phdr[0].p_offset < need) {
         need = phdr[0].p_offset;
      }
      patch_many_bytes(s.startEA, buf, need);

      doStruct(addr, sizeof(Elf32_Ehdr), elf_hdr);
      addr += elf->e_phoff;
      for (int i = 0; i < elf->e_phnum; i++) {
         doStruct(addr + i * sizeof(Elf32_Phdr), sizeof(Elf32_Phdr), elf_phdr);
      }
      free(buf);
      fclose(f);
   }
   return base_addr;
}

void initListEntry(dword le) {
   patch_long(le, le);              //Flink
   patch_long(le + 4, le);          //Blink
}

void initPebLdrData(dword pebLdrData) {
//   dword moduleList = pebLdrData + 0x1C;
   patch_long(pebLdrData - 4, 0);              //Count of loaded modules
   patch_long(pebLdrData, 0x24);              //Length
   patch_long(pebLdrData + 4, 1);          //Initialized

   initListEntry(pebLdrData + 0xC);  //InLoadOrderModuleList
   initListEntry(pebLdrData + 0x14);  //InMemoryOrderModuleList
   initListEntry(pebLdrData + 0x1C);  //InInitializationOrderModuleList

//   addModuleToPeb(0xdeadbeef, "ntdll.dll", true);  //placeholder for ntdll.dll

   char buf[260], *fname;
#if (IDA_SDK_VERSION < 490)
   fname = get_input_file_path();
#else
//   get_input_file_path(buf, sizeof(buf));
   get_root_filename(buf, sizeof(buf));
   fname = buf;
#endif

   addModuleToPeb(peImageBase, fname, true);
   addModule("kernel32.dll", true, 0);
   addModule("ntdll.dll", true, 0);
//   msg("peb modules added\n");
}

const char *win_xp_env[] = {
   "ALLUSERSPROFILE=C:\\Documents and Settings\\All Users",
   "APPDATA=C:\\Documents and Settings\\$USER\\Application Data",
   "CLIENTNAME=Console",
   "CommonProgramFiles=C:\\Program Files\\Common Files",
   "COMPUTERNAME=$HOST",
   "ComSpec=C:\\WINDOWS\\system32\\cmd.exe",
   "FP_NO_HOST_CHECK=NO",
   "HOMEDRIVE=C:",
   "HOMEPATH=\\Documents and Settings\\$USER",
   "LOGONSERVER=\\\\$HOST",
   "NUMBER_OF_PROCESSORS=1",
   "OS=Windows_NT",
   "Path=C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem",
   "PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH",
   "PROCESSOR_ARCHITECTURE=x86",
   "PROCESSOR_IDENTIFIER=x86 Family 6 Model 23 Stepping 10, GenuineIntel",
   "PROCESSOR_LEVEL=6",
   "PROCESSOR_REVISION=170a",
   "ProgramFiles=C:\\Program Files",
   "PROMPT=$P$G",
   "SESSIONNAME=Console",
   "SystemDrive=C:",
   "SystemRoot=C:\\WINDOWS",
   "TEMP=C:\\DOCUME~1\\$DOSUSER\\LOCALS~1\\Temp",
   "TMP=C:\\DOCUME~1\\$DOSUSER\\LOCALS~1\\Temp",
   "USERDOMAIN=$HOST",
   "USERNAME=$USER",
   "USERPROFILE=C:\\Documents and Settings\\$USER",
   "windir=C:\\WINDOWS",
   NULL
};

const char *linux_env[] = {
   "HOSTNAME=$HOST",
   "TERM=vt100",
   "SHELL=/bin/bash",
   "HISTSIZE=1000",
   "USER=$USER",
   "MAIL=/var/spool/mail/$USER",
   "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
   "PWD=/home/$USER",
   "LANG=en_US.UTF-8",
   "HISTCONTROL=ignoredups",
   "SHLVL=1",
   "HOME=/home/$USER",
   "LOGNAME=$USER",
   "LESSOPEN=|/usr/bin/lesspipe.sh %s",
   "G_BROKEN_FILENAMES=1",
   "OLDPWD=/tmp",
   NULL
};

//var must have been allocated using qalloc
char *replace(char *var, const char *match, const char *sub) {
   char *res, *find;
   while ((find = strstr(var, match)) != NULL) {
      *find = 0;
      find += strlen(match);
      int len = strlen(var) + strlen(sub) + strlen(find) + 1;
      res = (char*)qalloc(len);
      ::qsnprintf(res, len, "%s%s%s", var, sub, find);
      qfree(var);
      var = res;
   }
   return var;
}

Buffer *makeEnv(const char *env[], const char *userName, const char *hostName) {
   Buffer *res = new Buffer();
   for (int i = 0; env[i]; i++) {
      char *ev = ::qstrdup(env[i]);
      ev = replace(ev, "$USER", userName);
      ev = replace(ev, "$HOST", hostName);
      if (strlen(userName) > 8) {
         char buf[10];
         ::qstrncpy(buf, userName, 6);
         ::qstrncpy(buf + 6, "~1", 3);
         ev = replace(ev, "$DOSUSER", buf);
      }
      else {
         ev = replace(ev, "$DOSUSER", userName);
      }
      res->write(ev, strlen(ev) + 1);
      qfree(ev);
   }
   res->write("", 1);
   return res;
}

Buffer *makeLinuxEnv(const char *env[], const char *userName, const char *hostName) {
   Buffer *res = new Buffer();
   for (int i = 0; env[i]; i++) {
      char *ev = ::qstrdup(env[i]);
      ev = replace(ev, "$USER", userName);
      ev = replace(ev, "$HOST", hostName);
      res->write(ev, strlen(ev) + 1);
      qfree(ev);
   }
   return res;
}

//notification hook function for idb notifications
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
int idaapi idb_hook(void * /*user_data*/, int notification_code, va_list va) {
   if (notification_code == idb_event::byte_patched) {
      // A byte has been patched                      
      // in: ea_t ea                                  
      ea_t ea = va_arg(va, ea_t);
      segment_t *st = get_segm_by_name(".stack");
      if (st && st->contains(ea)) {
         ea &= 0xFFFFFFFC;   //round down to dword boundary
         dword val = get_long(ea);
         segment_t *seg = getseg(val);
         if (seg) {
            char name[256];
            ssize_t s = get_nice_colored_name(val, name, sizeof(name), GNCN_NOCOLOR);
            if (s != 0) {
               set_cmt(ea, name, false);
            }
         }
         else {
            set_cmt(ea, "", false);
         }
      }
   }
   return 0;
}
#endif

void formatStack(dword begin, dword end) {
   while (begin < end) {
      do_data_ex(begin, dwrdflag(), 4, BADNODE);
      begin += 4;
   }
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
   if (!idbHooked) {
      hook_to_notification_point(HT_IDB, idb_hook, NULL);
      idbHooked = true;
   }
#endif
}

void createIdt(dword idtBase, dword idtLimit) {
   MemMgr::mmap(idtBase, idtLimit, 0, 0, ".idt");
}

void createGdt(dword gdtBase, dword gdtLimit) {
   MemMgr::mmap(gdtBase, gdtLimit, 0, 0, ".gdt");
}

void createWindowsStack(dword /*top*/, dword /*size*/) {
   esp = 0x130000;
   dword base = esp - 0x4000;
   MemMgr::mmap(base, 0x4000, 0, 0, ".stack");
   formatStack(base, esp);

/*
   for (int i = 0; i < 16; i++) {
      push(0, SIZE_DWORD);
   }
*/
}

//possible modify to use CreateThread code for initial thread
dword createWindowsPEB() {
   //win2k peb is 7FFDF000
   //Win 7 PEB addresses range from 0x7ffd3000-0x7ffdf000 by 0x1000
   //0x7ffde000  is most common PEB address in Vista followed by 0x7ffdf000
   dword pebBase = 0x7ffdf000;
   MemMgr::mmap(pebBase, 0x1000, 0, 0, ".peb");
   patch_long(pebBase, 0);              //zero out BeingDebugged flag
   patch_long(pebBase + PEB_IMAGE_BASE, peImageBase);
   
   dword heapBase = (x86emu_node.altval(X86_MAXEA) + 0x1000) & 0xfffff000;
   dword heap = addHeapCommon(0x10000, heapBase);
   patch_long(pebBase + PEB_MAX_HEAPS, (0x1000 - SIZEOF_PEB) / 4);   //0x1000 == PAGE_SIZE
   patch_long(pebBase + PEB_PROCESS_HEAP, heap);
   patch_long(pebBase + PEB_NUM_HEAPS, 1);
   patch_long(pebBase + SIZEOF_PEB + 4, heap);
   
   // NEED TO MOVE LdrData out of the PEB
   // space from end of PEB to end of page is dedicated to 
   // heap admin
   dword pebLdrData = pebBase + 0x200;   //usually inside ntdll.dll
   patch_long(pebBase + PEB_LDR_DATA, pebLdrData);
   initPebLdrData(pebLdrData);
//   msg("peb created\n");

   patch_long(pebBase + PEB_TLS_BITMAP, pebBase + PEB_TLS_BITMAP_BITS);
   patch_long(pebBase + PEB_TLS_EXP_BITMAP, pebBase + PEB_TLS_EXP_BITMAP_BITS);

   //heap needs to be initialized here
   //env string is sequence of \0 terminated WCHAR pointed to by proc_parms + 0x48
   //this is allocated in heap
   //copy environment to this location as WCHAR
   const char *userName = "Administrator";
   const char *hostName = "localhost";
   Buffer *env = makeEnv(win_xp_env, userName, hostName);
   unsigned int len = env->get_wlen();
   unsigned char *eb = env->get_buf();
   dword env_buf = HeapBase::getHeap()->malloc(len * 2);
   for (unsigned int i = 0; i < len; i++) {
      patch_word(env_buf + 2 * i, eb[i]);
   }
   delete env;
   
   //allocate process parameters in heap right after env
   dword proc_parms = HeapBase::getHeap()->calloc(SIZEOF_PROCESS_PARAMETERS, 1);
   
   //command line needs to be pointed to by UNICODE_STRING at proc_parms + 0x40
   //need interface to accept command line from user
   const char *cmdLine = "dummy";
   int cmdLineLen = strlen(cmdLine) + 1;
   dword cmd_line = HeapBase::getHeap()->malloc(cmdLineLen * 2);
   //copy command line to this location as WCHAR
   for (int i = 0; i < cmdLineLen; i++) {
      patch_word(cmd_line + 2 * i, cmdLine[i]);
   }
   pCmdLineA = HeapBase::getHeap()->malloc(cmdLineLen);
   //copy command line to this location as CHAR
   for (int i = 0; i < cmdLineLen; i++) {
      patch_byte(pCmdLineA + i, cmdLine[i]);
   }

   patch_long(pebBase + PEB_PROCESS_PARMS, proc_parms);
   patch_word(proc_parms + 0x40, cmdLineLen * 2);
   patch_word(proc_parms + 0x42, cmdLineLen * 2);
   patch_long(proc_parms + 0x44, cmd_line);
   patch_long(proc_parms + PARMS_ENV_PTR, env_buf);

   x86emu_node.altset(EMU_COMMAND_LINE, pCmdLineA);

   patch_long(pebBase + PEB_OS_MAJOR, OSMajorVersion);   //varies with o/s personality
   patch_long(pebBase + PEB_OS_MINOR, OSMinorVersion);   //varies with o/s personality
   patch_long(pebBase + PEB_OS_BUILD, OSBuildNumber);   //varies with o/s personality
   patch_long(pebBase + PEB_OS_PLATFORM_ID, 2);    //OSPlatformId
   
   return pebBase;
}

void createWindowsTEB(dword peb) {   
   //teb address is highest address not occupied by peb, additional tebs are 
   //allocated in stack fashion at next lower page in memory, skiping peb page
   //is necessary
   ebx = peb;       //peb
   for (fsBase = 0x7ffdf000; fsBase == peb; fsBase -= 0x1000);   // this is teb address
   MemMgr::mmap(fsBase, 0x1000, 0, 0, ".teb");

   threadList = activeThread = new ThreadNode();
   dword tid = activeThread->id;
   
   dword pid = 0;
   getRandomBytes(&pid, 2);
   pid = (pid % 3000) + 1000;
   
   patch_long(fsBase + TEB_PROCESS_ID, pid);
   patch_long(fsBase + TEB_THREAD_ID, tid);

   patch_long(fsBase + TEB_LINEAR_ADDR, fsBase);  //teb self pointer
   patch_long(fsBase + TEB_PEB_PTR, ebx);     //peb self pointer   
   
   createWindowsStack(0x130000, 0x4000);
   patch_long(fsBase + TEB_STACK_TOP, 0x130000);     //top of stack   
   patch_long(fsBase + TEB_STACK_BOTTOM, 0x130000 - 0x4000);     //bottom of stack   

   push(0, SIZE_DWORD);
   push(nt.OptionalHeader.AddressOfEntryPoint + nt.OptionalHeader.ImageBase, SIZE_DWORD);
   push(0, SIZE_DWORD);
   push(0, SIZE_DWORD);
   push(0, SIZE_DWORD);

   //need kernel32.dll mapped prior to this
   dword k32 = myGetModuleHandle("kernel32.dll");
   push(k32, SIZE_DWORD);  //this should point into kernel32 somewhere

   //last chance exception handler
   push(myGetProcAddress(k32, "UnhandledExceptionFilter"), SIZE_DWORD);  //kernel32 exception handler
   push(0xffffffff, SIZE_DWORD);  //end of SEH list

   patch_long(fsBase, esp);  //last chance SEH record

   push(0, SIZE_DWORD);        //?????
   push(esp - 0x14, SIZE_DWORD);
   push(0, SIZE_DWORD);        //?????
   push(peb, SIZE_DWORD);        //?????
   push(0, SIZE_DWORD);
   push(0, SIZE_DWORD);        //?????

   //points to return address from which our entry point
   //was called
   //if entry is a tls callback, this is in ntdll.dll
   //which will go on to call into to the actual entry point
   //otherwise this is in kernel32.dll where
   //RtlExitUserThread gets called
   //need a reliable way to determine the offset into kernel32
   //could just use the address of TerminateProcess
   push(0x16fd7 + k32, SIZE_DWORD);
   
//   msg("teb created\n");
}

void createWindowsProcess() {
   dword peb = createWindowsPEB();
   createWindowsTEB(peb);
}

void buildWinMainArgs() {
   push(_SW_SHOW, SIZE_DWORD);     //nCmdShow
   push(pCmdLineA, SIZE_DWORD);    //lpCmdLine
   push(0, SIZE_DWORD);            //hPrevInstance
   push(peImageBase, SIZE_DWORD);  //hInstance
   push(0xbadf00d, SIZE_DWORD);  //dummy return address
   syncDisplay();
}

void buildDllMainArgs() {
   push(0, SIZE_DWORD);            //lpvReserved
   push(_DLL_PROCESS_ATTACH, SIZE_DWORD);            //fdwReason
   push(peImageBase, SIZE_DWORD);  //hinstDLL
   push(0xbadf00d, SIZE_DWORD);  //dummy return address
   syncDisplay();
}

void buildPEMainArgs() {
   syncDisplay();
}

void buildElfMainArgs() {
   dword envp;
   dword argv;
   int argc = 0;
   int envc = 0;

   dword ch = elfEnvStart;
   while (get_byte(ch++)) {
      while (get_byte(ch++));
      envc++;
   }
   push(0, SIZE_DWORD);
   if (envc) {
      dword *env = (dword*)malloc(envc * sizeof(dword*));
      ch = elfEnvStart;
      int i = 0;
      do {
         env[i++] = ch++;
         while (get_byte(ch++));
      } while (get_byte(ch));
      do {
         push(env[--i], SIZE_DWORD);
      } while (i);
      free(env);
   }
   envp = esp;

   ch = elfArgStart;
   while (get_byte(ch++)) {
      while (get_byte(ch++));
      argc++;
   }
   push(0, SIZE_DWORD);
   if (argc) {
      dword *args = (dword*)malloc(argc * sizeof(dword*));
      ch = elfArgStart;
      int i = 0;
      do {
         args[i++] = ch++;
         while (get_byte(ch++));
      } while (get_byte(ch));
      do {
         push(args[--i], SIZE_DWORD);
      } while (i);
      free(args);
   }
   argv = esp;
   
   push(envp, SIZE_DWORD);
   push(argv, SIZE_DWORD);
   push(argc, SIZE_DWORD);
   
   //push address in start for main to return to
   push(0xbadf00d, SIZE_DWORD);  //dummy return address
   syncDisplay();
}

void buildMainArgs() {
   if (inf.filetype == f_PE) {
      buildPEMainArgs();
   }
   else if (inf.filetype == f_ELF) {
      buildElfMainArgs();
   }
}

void parseMainArgs() {
/*
   //count args
   mainArgs = (char*)malloc(argc * sizeof(char*));
   int j = 0;
   for (int i = 0; i < argc; i++) {
      mainArgs[i] = cmdLine + j;
      while (cmdLine[j] != ' ') j++;
   }
*/
}

void buildElfArgs() {
   char buf[260], *fname;
#if (IDA_SDK_VERSION < 490)
   fname = get_input_file_path();
#else
//   get_input_file_path(buf, sizeof(buf));
   get_root_filename(buf, sizeof(buf));
   fname = buf;
#endif
   parseMainArgs();
   push(0, SIZE_BYTE);
   if (mainArgs) {
      int argc = 0;
      char **arg = mainArgs;
      while (*arg) argc++;
      while (argc--) {
         int len = strlen(mainArgs[argc]) + 1;
         put_many_bytes(esp - len, mainArgs[argc], len);
         esp -= len;
      }
   }
   int len = strlen(fname) + 1;
   put_many_bytes(esp - len, fname, len);
   esp -= len;
   //add other environment strings
   elfArgStart = esp;
   esp &= 0xFFFFFFFC;
}

void buildElfEnvironment(dword elf_base) {
   char buf[260], *fname;
   char path[260];
#if (IDA_SDK_VERSION < 490)
   fname = get_input_file_path();
#else
//   get_input_file_path(buf, sizeof(buf));
   get_root_filename(buf, sizeof(buf));
   fname = buf;
#endif
   //build environment
   const char *userName = "test";
   const char *hostName = "localhost";
   Buffer *env = makeLinuxEnv(linux_env, userName, hostName);
   unsigned int env_len = env->get_wlen();
   char *eb = (char*)env->get_buf();
   //find PWD
   char *pwd = NULL;
   for (unsigned int i = 0; i < (env_len - 4); i++) {
      if (strncmp(eb + i, "PWD=", 4) == 0) {
         pwd = eb + i + 4;
         break;
      }
   }
   if (pwd) {
      ::qsnprintf(path, sizeof(path), "%s/%s", pwd, fname);
      fname = path;
   }

   push(0, SIZE_DWORD);
   int len = strlen(fname) + 1;
   esp -= len;
   dword fileName = esp;
   put_many_bytes(esp, fname, len);
   esp -= 2;
   put_many_bytes(esp, "_=", 2);

   //add other environment strings
   esp -= env_len;
   put_many_bytes(esp, eb, env_len);
   elfEnvStart = esp;
   
   //add argument strings, for now only exe name
   dword argc = 1;
   esp -= len;
   put_many_bytes(esp, fname, len);
   elfArgStart = esp;
   
   esp &= 0xFFFFFFFC;
   
   //need to create elf tables in here as well

   esp -= 5;
   put_many_bytes(esp, "i686", 5);
   
   dword platform = esp;

   unsigned char rbytes[16];
   getRandomBytes(rbytes, 16);
   esp -= 16;
   put_many_bytes(esp, rbytes, 16);    //AT_RANDOM
   dword random = esp;

   esp &= 0xfffffffc;

   push(0, SIZE_DWORD);
   push(0, SIZE_DWORD);
   push(0, SIZE_DWORD);
   push(0, SIZE_DWORD);

   push(platform, SIZE_DWORD);
   push(AT_PLATFORM, SIZE_DWORD);

   push(fileName, SIZE_DWORD);
   push(AT_EXECFN, SIZE_DWORD);

   push(random, SIZE_DWORD);
   push(AT_RANDOM, SIZE_DWORD);

   push(0, SIZE_DWORD);
   push(AT_SECURE, SIZE_DWORD);

   push(0, SIZE_DWORD);   //need beter gid
   push(AT_EGID, SIZE_DWORD);

   push(0, SIZE_DWORD);   //need better gid
   push(AT_GID, SIZE_DWORD);

   push(0, SIZE_DWORD);   //need better uid
   push(AT_EUID, SIZE_DWORD);

   push(0, SIZE_DWORD);   //need better uid
   push(AT_UID, SIZE_DWORD);

   push(get_name_ea(BADADDR, "start"), SIZE_DWORD);
   push(AT_ENTRY, SIZE_DWORD);

   push(0, SIZE_DWORD);
   push(AT_FLAGS, SIZE_DWORD);

   push(0, SIZE_DWORD);
   push(AT_BASE, SIZE_DWORD);

   push(get_word(elf_base + 44), SIZE_DWORD);
   push(AT_PHNUM, SIZE_DWORD);

   push(get_word(elf_base + 42), SIZE_DWORD);
   push(AT_PHENT, SIZE_DWORD);

   push(get_word(elf_base + 28) + elf_base, SIZE_DWORD);
   push(AT_PHDR, SIZE_DWORD);

   push(100, SIZE_DWORD);
   push(AT_CLKTCK, SIZE_DWORD);

   push(0x1000, SIZE_DWORD);
   push(AT_PAGESZ, SIZE_DWORD);

   push(0x0183f1ff, SIZE_DWORD);
   push(AT_HWCAP, SIZE_DWORD);

   push(0x110000, SIZE_DWORD); //((unsigned long)current->mm->context.vdso)
   push(AT_SYSINFO_EHDR, SIZE_DWORD);  //VDSO_CURRENT_BASE

   push(0x110414, SIZE_DWORD);   //((unsigned long)VDSO32_SYMBOL(VDSO_CURRENT_BASE, vsyscall))
   push(AT_SYSINFO, SIZE_DWORD);  //VDSO_ENTRY

   //end elf interpreter setup

   push(0, SIZE_DWORD);
   //push envp
   dword envc = 0;
   dword loc = elfEnvStart;
   while (get_byte(loc)) {
      envc++;
      while (get_byte(loc++));
      loc++;
   }
   esp -= 4 * envc;
   envc = 0;
   loc = elfEnvStart;
   while (get_byte(loc)) {
      writeDword(esp + envc * 4, loc);
      envc++;
      while (get_byte(loc++));
   }
   delete env;

   push(0, SIZE_DWORD);  //NULL termiante argv
   //push argv
   loc = elfArgStart;
   argc = 0;
   while (loc < elfEnvStart) {
      argc++;
      while (get_byte(loc++));
   }
   esp -= 4 * argc;
   argc = 0;
   loc = elfArgStart;
   while (loc < elfEnvStart) {
      writeDword(esp + argc * 4, loc);
      argc++;
      while (get_byte(loc++));
   }
   
   push(argc, SIZE_DWORD);      
}

void createElfStack() {
   esp = 0xC0000000;
   dword base = esp - 0x4000;
   MemMgr::mmap(base, 0x4000, 0, 0, ".stack");
   formatStack(base, esp);
}

void createElfHeap() {
   dword base = (x86emu_node.altval(X86_MAXEA) + 0x1000) & 0xfffff000;
   HeapBase::addHeap(0x10000, base);
}

bool haveStackSegment() {
   return get_segm_by_name(".stack") != NULL;
}

bool haveHeapSegment() {
   return get_segm_by_name(".heap") != NULL;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
int idaapi init(void) {
   cpuInit = false;
   
   if (strcmp(inf.procName, "metapc")) return PLUGIN_SKIP;

//   msg(PLUGIN_NAME": hooking idp\n");
   hook_to_notification_point(HT_IDP, idpCallback, NULL);
   idpHooked = true;

   resetCpu();

   return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
#ifdef DEBUG
   msg(PLUGIN_NAME": term entered\n");
#endif   
   if (hProv) {
#ifdef __NT__
      CryptReleaseContext(hProv, 0);
#else
      close(hProv);
#endif
   }
   if (uiHooked) {
      unhook_from_notification_point(HT_UI, uiCallback, NULL);
      uiHooked = false;
      unregister_funcs();
   }
   if (idpHooked) {
      idpHooked = false;
      unhook_from_notification_point(HT_IDP, idpCallback, NULL);
   }   
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
   if (idbHooked) {
      idbHooked = false;
      unhook_from_notification_point(HT_IDB, idb_hook, NULL);
   }
#endif
   destroyEmulatorWindow();
   closeTrace();
   doTrace = false;
   doTrack = false;
   doLogLib = false;
#ifdef DEBUG
   msg(PLUGIN_NAME": term exiting\n");
#endif   
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void idaapi run(int /*arg*/) {
   if (!isWindowCreated) {
      if (!netnode_exist(x86emu_node)) {
         //save basic info first time we encounter this database
         //BUT don't mark emulator as initialized
         //NOTE - should also save original PE headers as a blob at this point
         //they may not be available by the time the user decides to run the plugin
         GetSystemTimeAsFileTime(&baseTime);
         x86emu_node.create(x86emu_node_name);

         segment_t *s = get_first_seg();
         if (s && (s->startEA & 0xFFF)) {
            dword currstart = s->startEA;
            dword newstart = s->startEA & ~0xFFF;
            set_segm_start(s->startEA, newstart, SEGMOD_SILENT);
            for (dword i = newstart; i < currstart; i++) {
               patch_byte(i, 0);
            }
         }
         
         x86emu_node.altset(X86_MINEA, inf.minEA);
         
         s = get_last_seg();
         if (s && (s->endEA & 0xFFF)) {
            dword currend = s->endEA;
            dword newend = (s->endEA + 0xFFF) & ~0xFFF;
            set_segm_end(s->startEA, newend, SEGMOD_SILENT);
            for (dword i = currend; i < newend; i++) {
               patch_byte(i, 0);
            }
         }
         
         x86emu_node.altset(X86_MAXEA, inf.maxEA);
         getRandomBytes(&randVal, 4);
         x86emu_node.altset(X86_RANDVAL, randVal);
   
         x86emu_node.altset(SYSTEM_TIME_LOW, baseTime.dwLowDateTime);
         x86emu_node.altset(SYSTEM_TIME_HIGH, baseTime.dwHighDateTime);
         
         getRandomBytes(&tsc, 6);
         char *t = (char*)&tsc;
         t[5] &= 3;              //truncate time somewhat

         kernel_node.create(kernel_node_name);
         if (inf.filetype == f_PE || inf.filetype == f_PDF) {
            //need to allow this to be user selectable at some point
            os_personality = PERS_WINDOWS_XP;
            
            kernel_node.altset(OS_MAX_FILES, WIN_MAX_FILES);
            kernel_node.altset(OS_PAGE_SIZE, WIN_PAGE_SIZE);
            kernel_node.altset(OS_STACK_TOP, WIN_STACK_TOP);
            kernel_node.altset(OS_STACK_SIZE, WIN_STACK_SIZE);
            kernel_node.altset(OS_MIN_ADDR, WIN_ALLOC_MIN);
            kernel_node.altset(OS_MAX_ADDR, WIN_TASK_SIZE_MAX);
            kernel_node.altset(OS_IDT_BASE, WIN_IDT_BASE);
            kernel_node.altset(OS_IDT_LIMIT, WIN_IDT_LIMIT);
            kernel_node.altset(OS_GDT_BASE, WIN_GDT_BASE);
            kernel_node.altset(OS_GDT_LIMIT, WIN_GDT_LIMIT);
            
         }
         else if (inf.filetype == f_ELF) {
            //need to allow this to be user selectable at some point
            //need a better assumption than ELF == Linux
            os_personality = PERS_LINUX_26;

            kernel_node.altset(OS_MAX_FILES, LINUX_MAX_FILES);
            kernel_node.altset(OS_PAGE_SIZE, LINUX_PAGE_SIZE);
            kernel_node.altset(OS_STACK_TOP, LINUX_STACK_TOP);
            kernel_node.altset(OS_STACK_SIZE, LINUX_STACK_SIZE);
            kernel_node.altset(OS_MIN_ADDR, LINUX_ALLOC_MIN);
            kernel_node.altset(OS_MAX_ADDR, LINUX_TASK_SIZE_MAX);
            kernel_node.altset(OS_IDT_BASE, LINUX_IDT_BASE);
            kernel_node.altset(OS_IDT_LIMIT, LINUX_IDT_LIMIT);
            kernel_node.altset(OS_GDT_BASE, LINUX_GDT_BASE);
            kernel_node.altset(OS_GDT_LIMIT, LINUX_GDT_LIMIT);

            kernel_node.altset(OS_LINUX_BRK, inf.maxEA);
         }
         x86emu_node.altset(OS_PERSONALITY, os_personality);
      }      
      
      //test for presence of personality
      //show personality dialog based on file type
      //differs for PE vs ELF
      //for ELF differs for Linux vs FreeBSD
      //create personality, heap, peb, teb
      //choose CPUID features regardless of file type
      dword elf_base = 0;
      if (inf.filetype == f_PE && !netnode_exist(petable_node)) {
         //init some PE specific stuff
         dword headerBase = PELoadHeaders();
         msg("headerBase is %x, valid = %d\n", headerBase, pe.valid);
         if (headerBase != 0xFFFFFFFF) {
            push(headerBase, SIZE_DWORD);
            push(0, SIZE_DWORD);
            dword pe_offset = headerBase + get_long(headerBase + 0x3C);
            get_many_bytes(pe_offset, &nt, sizeof(nt));
   
            if (pe.valid) {
               msg("pe struct is valid, calling doImports\n");
               createWindowsProcess();
               doImports(pe);
            }
            else {
               msg("x86emu: invalid pe table struct\n");
            }
         }
         else {
//            msg("headerBase == 0xFFFFFFFF\n");
         }
      }
      else if (inf.filetype == f_ELF) {
         //init some ELF specific stuff
         elf_base = ELFLoadHeaders();
      }
      else if (inf.filetype == f_PDF) {
         peImageBase = 0x400000;
         createWindowsProcess();
      }
      if (!cpuInit) {
         dword init_eip = get_screen_ea();
         dword idtBase = 0;
         dword idtLimit = 0x800;
         dword gdtBase = 0;
         dword gdtLimit = 0x400;
         if (inf.filetype == f_PE || inf.filetype == f_PDF) {
            enableSEH();
            //typical values for Windows XP segment registers
            _es = _ss = _ds = 0x23;   //0x167 for win98
            _cs = 0x1b;             //0x15F for win98
            _fs = 0x38;             //0xE1F for win98
            esi = 0xffffffff;
            ecx = esp - 0x14;
            ebp = 0x12fff0;
            
            cpu.eflags |= 0x3000;  //ring 3
            
            idtBase = WIN_IDT_BASE;
            idtLimit = WIN_IDT_LIMIT;
            gdtBase = WIN_GDT_BASE;
            gdtLimit = WIN_GDT_LIMIT;
            
         }
         else { //"elf" and others land here
            //need to properly handle brk and heap creation
//            createElfHeap();   //do this first so it goes right after exe
            createElfStack();
            buildElfEnvironment(elf_base);
            //create initial thread
            threadList = activeThread = new ThreadNode();

            _es = _ss = _ds = 0x7b;
            _cs = 0x73;
            _fs = 0;
            _gs = 0;

            cpu.eflags |= 0x3000;  //ring 3

            idtBase = LINUX_IDT_BASE;
            idtLimit = LINUX_IDT_LIMIT;
            gdtBase = LINUX_GDT_BASE;
            gdtLimit = LINUX_GDT_LIMIT;
         }
         createIdt(idtBase, idtLimit);
         createGdt(gdtBase, gdtLimit);
         initProgram(init_eip, idtBase, idtLimit);
         initGDTR(gdtBase, gdtLimit);
      }

      pCmdLineA = x86emu_node.altval(EMU_COMMAND_LINE);  

#if IDA_SDK_VERSION >= 530
      TForm *stackForm = open_disasm_window("Stack");
      switchto_tform(stackForm, true);
      stackCC = get_current_viewer();
      mainForm = find_tform("IDA View-A");
      switchto_tform(mainForm, true);
#endif
      if (!cpuInit) {
         cpu.eip = get_screen_ea();
      }
      isWindowCreated = createEmulatorWindow();
   }
   if (isWindowCreated) {
      displayEmulatorWindow();
   }
   if (!uiHooked) {
      uiHooked = true;
      hook_to_notification_point(HT_UI, uiCallback, NULL);
      register_funcs();
   }
   
}

//--------------------------------------------------------------------------
char comment[] = "This is an x86 emulator";

char help[] =
        "An x86 emulation module\n"
        "\n"
        "This module allows you to step through an x86 program.\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "x86 Emulator";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F8";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

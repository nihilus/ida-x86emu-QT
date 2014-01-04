/*
   Source for x86 emulator IdaPro plugin
   File: emufuncs.cpp
   Copyright (c) 2004-2010, Chris Eagle
   
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

#ifdef __NT__

#include <windows.h>
#include <winnt.h>

#else 

#include <wctype.h>
#include "image.h"

#endif

#include <ctype.h>

#ifdef PACKED
#undef PACKED
#endif

#include "x86emu_ui.h"
#include "cpu.h"
#include "context.h"
#include "emufuncs.h"
#include "emuheap.h"
#include "hooklist.h"
#include "emuthreads.h"
#include "buffer.h"
#include "peutils.h"
#include "memmgr.h"
#include "linux_syscalls.h"
#include "bsd_syscalls.h"

#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <segment.hpp>

#if IDA_SDK_VERSION < 530
#define SEGMOD_SILENT 0
#define SEGMOD_KEEP 0
#endif

void addVectoredExceptionHandler(bool first, dword handler);
void removeVectoredExceptionHandler(dword handler);

#define FAKE_HANDLE_BASE 0x80000000

extern HWND x86Dlg;

struct FakedImport {
   dword handle;  //module handle the lookup was performed on
   dword addr;    //returned fake import address
   char *name;    //name assigned to this function
   FakedImport *next;
};

static HandleNode *moduleHead = NULL;
static FunctionInfo *functionInfoList = NULL;

static FakedImport *fakedImportList = NULL;
//static dword fakedImportAddr = 1;

//stick dummy values up in kernel space to distinguish them from
//actual library handles
static dword moduleHandle = FAKE_HANDLE_BASE;    

//persistant module identifier
static dword moduleId = 0x10000;

static unemulatedCB unemulated_cb = NULL;

typedef enum {R_FAKE = -1, R_NO = 0, R_YES = 1} Reply;

int emu_alwaysLoadLibrary = ASK;
int emu_alwaysGetModuleHandle = ASK;

dword pCmdLineA;

//pointer to til we use to extract function info
til_t *ti = NULL;

HookEntry hookTable[] = {
   {"CreateThread", emu_CreateThread},
   {"VirtualAlloc", emu_VirtualAlloc},
   {"VirtualFree", emu_VirtualFree},
   {"VirtualProtect", emu_VirtualProtect},
   {"LocalLock", emu_LocalLock},
   {"LocalUnlock", emu_LocalUnlock},
   {"LocalAlloc", emu_LocalAlloc},
   {"LocalReAlloc", emu_LocalReAlloc},
   {"LocalFree", emu_LocalFree},
   {"GetProcAddress", emu_GetProcAddress},
   {"GetModuleHandleA", emu_GetModuleHandleA},
   {"GetModuleHandleW", emu_GetModuleHandleW},
   {"FreeLibrary", emu_FreeLibrary},
   {"LoadLibraryA", emu_LoadLibraryA},
   {"LoadLibraryW", emu_LoadLibraryW},
   {"LoadLibraryExA", emu_LoadLibraryExA},
   {"LoadLibraryExW", emu_LoadLibraryExW},
   {"HeapCreate", emu_HeapCreate},
   {"HeapDestroy", emu_HeapDestroy},
   {"GlobalAlloc", emu_GlobalAlloc},
   {"GlobalFree", emu_GlobalFree},
   {"GlobalLock", emu_GlobalLock},
   {"HeapAlloc", emu_HeapAlloc},
   {"HeapSize", emu_HeapSize},
   {"RtlAllocateHeap", emu_HeapAlloc},
   {"HeapFree", emu_HeapFree},
   {"GetProcessHeap", emu_GetProcessHeap},
   {"malloc", emu_malloc},
   {"calloc", emu_calloc},
   {"realloc", emu_realloc},
   {"free", emu_free},
   {"IsDebuggerPresent", emu_IsDebuggerPresent},
   {"CheckRemoteDebuggerPresent", emu_CheckRemoteDebuggerPresent},
   {"CloseHandle", emu_CloseHandle},
   {"NtQuerySystemInformation", emu_NtQuerySystemInformation},
   {"NtQueryInformationProcess", emu_NtQueryInformationProcess},
   {"NtSetInformationThread", emu_NtSetInformationThread},
   {"lstrlen", emu_lstrlen},
   {"lstrcpy", emu_lstrcpy},
   {"strncpy", emu_strncpy},
   {"strcpy", emu_strcpy},
   {"lstrcpyW", emu_lstrcpyW},
   {"lstrcat", emu_lstrcat},
   {"strcat", emu_strcat},
   {"_wcsset", emu_wcsset},
   {"_strlwr", emu_strlwr},

   {"GetCurrentProcess", emu_GetCurrentProcess},
   {"GetCurrentProcessId", emu_GetCurrentProcessId},
   {"GetCurrentThreadId", emu_GetCurrentThreadId},
   {"GetThreadContext", emu_GetThreadContext},

   {"RevertToSelf", emu_RevertToSelf},
   {"AreAnyAccessesGranted", emu_AreAnyAccessesGranted},
   {"GetBkMode", emu_GetBkMode},
   {"GdiFlush", emu_GdiFlush},
   {"GetROP2", emu_GetROP2},
   {"GetBkColor", emu_GetBkColor},
   {"GdiGetBatchLimit", emu_GdiGetBatchLimit},

   {"StrChrIW", emu_StrChrIW},
   {"StrChrIA", emu_StrChrIA},
   {"StrCmpIW", emu_StrCmpIW},
   {"StrCmpNIW", emu_StrCmpNIW},
   {"StrCmpW", emu_StrCmpW},
   {"StrCmpNW", emu_StrCmpNW},
   {"StrCpyW", emu_StrCpyW},
   {"StrSpnA", emu_StrSpnA},
   {"StrCSpnIA", emu_StrCSpnIA},
   {"StrCSpnIW", emu_StrCSpnIW},

   {"GetACP", emu_GetACP},
   {"GetClientRect", emu_GetClientRect},
   {"IsCharUpperA", emu_IsCharUpperA},
   {"IsCharAlphaA", emu_IsCharAlphaA},
   {"GetIconInfo", emu_GetIconInfo},
   {"GetWindow", emu_GetWindow},
   {"IsChild", emu_IsChild},
   {"GetTopWindow", emu_GetTopWindow},
   {"GetWindowContextHelpId", emu_GetWindowContextHelpId},
   {"WindowFromDC", emu_WindowFromDC},
   {"GetWindowPlacement", emu_GetWindowPlacement},
   {"CopyIcon", emu_CopyIcon},
   {"IsIconic", emu_IsIconic},
   {"GetGUIThreadInfo", emu_GetGUIThreadInfo},
   {"GetDC", emu_GetDC},
   {"GetTitleBarInfo", emu_GetTitleBarInfo},
   {"IsWindowUnicode", emu_IsWindowUnicode},
   {"IsMenu", emu_IsMenu},
   {"GetWindowRect", emu_GetWindowRect},
   {"IsWindowVisible", emu_IsWindowVisible},
   {"GetForegroundWindow", emu_GetForegroundWindow},
   {"InSendMessage", emu_InSendMessage},
   {"GetWindowTextA", emu_GetWindowTextA},
   {"IsUserAnAdmin", emu_IsUserAnAdmin},

   {"GetVersionExA", emu_GetVersionExA},
   {"GetVersion", emu_GetVersion},
   {"GetTickCount", emu_GetTickCount},

   {"GetSystemTimeAsFileTime", emu_GetSystemTimeAsFileTime},
   {"QueryPerformanceCounter", emu_QueryPerformanceCounter},

   {"NtAllocateVirtualMemory", emu_NtAllocateVirtualMemory},
   {"LdrLoadDll", emu_LdrLoadDll},
   {"LdrGetProcedureAddress", emu_LdrGetProcedureAddress},

   {"InterlockedIncrement", emu_InterlockedIncrement},
   {"InterlockedDecrement", emu_InterlockedDecrement},
   {"EncodePointer", emu_EncodePointer},
   {"DecodePointer", emu_DecodePointer},

   {"InitializeCriticalSection", emu_InitializeCriticalSection},
   {"InitializeCriticalSectionAndSpinCount", emu_InitializeCriticalSectionAndSpinCount},
   {"TryEnterCriticalSection", emu_TryEnterCriticalSection},
   {"EnterCriticalSection", emu_EnterCriticalSection},
   {"LeaveCriticalSection", emu_LeaveCriticalSection},
   {"DeleteCriticalSection", emu_DeleteCriticalSection},

   {"AddVectoredExceptionHandler", emu_AddVectoredExceptionHandler},
   {"RemoveVectoredExceptionHandler", emu_RemoveVectoredExceptionHandler},

   {"Sleep", emu_Sleep},

   {"GetLastError", emu_GetLastError},
   {"SetLastError", emu_SetLastError},

   {"TlsAlloc", emu_TlsAlloc},
   {"TlsFree", emu_TlsFree},
   {"TlsGetValue", emu_TlsGetValue},
   {"TlsSetValue", emu_TlsSetValue},

   {"FlsAlloc", emu_FlsAlloc},
   {"FlsFree", emu_TlsFree},
   {"FlsGetValue", emu_TlsGetValue},
   {"FlsSetValue", emu_TlsSetValue},

   {"GetEnvironmentStrings", emu_GetEnvironmentStringsA},
   {"GetEnvironmentStringsA", emu_GetEnvironmentStringsA},
   {"GetEnvironmentStringsW", emu_GetEnvironmentStringsW},
   {"FreeEnvironmentStringsA", emu_FreeEnvironmentStringsA},
   {"FreeEnvironmentStringsW", emu_FreeEnvironmentStringsW},
   {"GetCommandLineA", emu_GetCommandLineA},
   {"GetCommandLineW", emu_GetCommandLineW},

   {"GetStdHandle", emu_GetStdHandle},
   {"GetStartupInfoA", emu_GetStartupInfoA},
   {"GetStartupInfoW", emu_GetStartupInfoW},

   {"GetCPInfo", emu_GetCPInfo},

   {"WideCharToMultiByte", emu_WideCharToMultiByte},
   {"MultiByteToWideChar", emu_MultiByteToWideChar},
   {"GetStringTypeW", emu_GetStringTypeW},
   {"GetStringTypeA", emu_GetStringTypeA},
   {"LCMapStringW", emu_LCMapStringW},
   {"LCMapStringA", emu_LCMapStringA},
   
   {"GetLocaleInfoA", emu_GetLocaleInfoA},
   {"GetLocaleInfoW", emu_GetLocaleInfoW},

   {"GetWindowsDirectoryA", emu_GetWindowsDirectoryA},
   {"GetWindowsDirectoryW", emu_GetWindowsDirectoryW},
   {"GetSystemDirectoryA", emu_GetSystemDirectoryA},
   {"GetSystemDirectoryW", emu_GetSystemDirectoryW},

   {NULL, NULL}
};

void setThreadError(dword err) {
   writeDword(fsBase + TEB_LAST_ERROR, err);
}

/*
 * check for presence of extension, if missing add
 * .dll
 * module must be a malloced pointer
 */
char *checkModuleExtension(char *module) {
   if (module == NULL) return NULL;
   char *result = module;
   char *dot = strchr(module, '.');
   int len = strlen(module);
   if (dot == NULL) {
      int newlen = len + 5;
      result = (char*)realloc(module, newlen);
      if (result) {
         qstrncat(result, ".dll", newlen);
      }
   }
   else {
      if (dot[1] == 0) {
         // single . used to indicate no extension
         *dot = 0;
      }
   }
   return result;
}

HandleNode *findModuleByName(const char *h) {
   HandleNode *hl;
   if (h == NULL) return NULL;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (stricmp(h, hl->moduleName) == 0) break;
   }
   return hl;
}

dword myGetModuleHandle(const char *modName) {
   HandleNode *h = findModuleByName(modName);
   if (h == NULL) return 0xFFFFFFFF;
   return h->handle;
}

HandleNode *findModuleByHandle(dword handle) {
   HandleNode *hl;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (hl->handle == handle) break;
      if (hl->id == handle) break;       //for compatibility with old handle assignment style
   }
   return hl;
}

//return the end address of a loaded module
//useful to deconflict in the case we loaded module headers only
//return module end address or 0xffffffff for invalid handle
dword getModuleEnd(dword handle) {
   HandleNode *hl;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (hl->handle == handle) break;
   }
   if (hl) {
      dword nt = handle + get_long(handle + 0x3C); //e_lfanew
      return handle + get_long(nt + 0x50); //nt.OptionalHeader.SizeOfImage
   }
   return 0xffffffff;
}

/*
unsigned int getPEoffset(HMODULE mod) {
   IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER*) mod;
   if (mod >= (HMODULE)FAKE_HANDLE_BASE) return 0;
   if (hdr->e_magic == IMAGE_DOS_SIGNATURE) {
      return hdr->e_lfanew;
   }
   return 0;
}

IMAGE_NT_HEADERS *getPEHeader(HMODULE mod) {
   unsigned int offset = getPEoffset(mod);
   if (offset == 0) return NULL;
   IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)(offset + (char*)mod);
   if (pe->Signature != IMAGE_NT_SIGNATURE) {
      pe = NULL;
   }
   return pe;
}
*/

//find an existing faked import
FakedImport *findFakedImportByAddr(HandleNode *mod, dword addr) {
   FakedImport *ff = NULL;
   for (ff = fakedImportList; ff; ff = ff->next) {
      if (ff->handle == mod->handle && ff->addr == addr) break;
   }
   return ff;
}

FakedImport *findFakedImportByName(HandleNode *mod, char *procName) {
   FakedImport *ff = NULL;
   for (ff = fakedImportList; ff; ff = ff->next) {
      if (ff->handle == mod->handle && strcmp(ff->name, procName) == 0) break;
   }
   return ff;
}

//add a new faked import after first searching to see if it is already present
FakedImport *addFakedImport(HandleNode *mod, char *procName) {
   FakedImport *ff = findFakedImportByName(mod, procName);
   if (ff) return ff;
   ff = (FakedImport*)malloc(sizeof(FakedImport));
   ff->next = fakedImportList;
   ff->addr = mod->maxAddr++;
   ff->name = _strdup(procName);
   ff->handle = mod->handle;
   fakedImportList = ff;
   return ff;
}

/*
typedef struct _LDR_MODULE {
   LIST_ENTRY InLoadOrderModuleList;                   +0
   LIST_ENTRY InMemoryOrderModuleList;                 +8
   LIST_ENTRY InInitializationOrderModuleList;         +16
   PVOID BaseAddress;                                  +24
   PVOID EntryPoint;                                   +28
   ULONG SizeOfImage;                                  +32
   UNICODE_STRING FullDllName;                         +36 
   UNICODE_STRING BaseDllName;                         +44
   ULONG Flags;                                        +52
   SHORT LoadCount;                                    +56
   SHORT TlsIndex;                                     +58
   LIST_ENTRY HashTableEntry;                          +60
   ULONG TimeDateStamp;                                +68
} LDR_MODULE, *PLDR_MODULE;
*/

/*
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY  *Flink;
  struct _LIST_ENTRY  *Blink;
} LIST_ENTRY, *PLIST_ENTRY;
*/

/*
typedef struct _UNICODE_STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
*/

#define PEB_LDR_DATA_SIZE 0x24
#define LDR_MODULE_SIZE 0x48
#define BASE_ADDRESS_OFFSET 24
#define BASE_NAME_OFFSET 44

dword getModuleBase(dword ldrModule) {
   return get_long(ldrModule + BASE_ADDRESS_OFFSET);
}

void insertTail(dword listHead, dword mod, int doff) {
//   msg("Insert tail called to add %x to %x\n", mod, listHead);
   dword handle = getModuleBase(mod);
   dword modFlink = mod + 24 - doff;
   dword blink = listHead;
   dword flink;
   for (flink = get_long(listHead); 
        flink != listHead; 
        flink = get_long(flink)) {
      if (get_long(flink + doff) == handle) return; //already in list
      blink = flink;
   }
   blink = get_long(listHead + 4);
   patch_long(blink, modFlink);
   patch_long(modFlink, listHead);  //point mod fwd to head
   patch_long(modFlink + 4, blink);  //point mod back to former tail
   patch_long(listHead + 4, modFlink);  //link back to mod
}

void insertHead(dword listHead, dword mod, int doff) {
//   msg("Insert head called to add %x to %x\n", mod, listHead);
   dword handle = getModuleBase(mod);
//   msg("handle is %x mod is %x\n", handle, mod);
   dword modFlink = mod + 24 - doff;
//   msg("modFlink is %x\n", modFlink);
   dword flink;
//   msg("listHead is %x\n", listHead);
   for (flink = get_long(listHead); 
        flink != listHead; 
        flink = get_long(flink)) {
//      msg("first check flink = %x\n", flink);
      if (get_long(flink + doff) == handle) return; //already in list
   }
   flink = get_long(listHead);
   /*dword back =*/ get_long(flink + 4);
   patch_long(flink + 4, modFlink);
   patch_long(modFlink + 4, listHead);  //point mod back to head
   patch_long(modFlink, flink);  //point mod fwd to former head
   patch_long(listHead, modFlink);  //link fwd to mod
}

void insertInOrder(dword listHead, dword mod, int doff) {
//   msg("Insert in order called to add %x to %x\n", mod, listHead);
   dword handle = getModuleBase(mod);
   dword modFlink = mod + 24 - doff;
   dword blink = listHead;
   dword flink;
   for (flink = get_long(listHead); 
        flink != listHead; 
        flink = get_long(flink)) {
      dword modBase = get_long(flink + doff);
      if (modBase == handle) return; //already in list
      if (modBase > handle) break; //insert before this
      blink = flink;
   }
   //insert prior to flink
   blink = get_long(flink + 4);
   patch_long(blink, modFlink);
   patch_long(modFlink, flink);  //point mod back to head
   patch_long(modFlink + 4, blink);  //point mod fwd to former head
   patch_long(flink + 4, modFlink);  //link fwd to mod
}

bool containsModule(dword listHead, dword mod, int doff) {
   for (dword flink = get_long(listHead); 
        flink != listHead; 
        flink = get_long(flink)) {
      if (get_long(flink + doff) == mod) return true; //already in list
   }
   return false;
}

bool cmp_c_to_dbuni(char *cstr, dword uni) {
   dword ustr = get_long(uni + 4);
   if (ustr) {
      do {
         char ch = *cstr++;
         short s = get_word(ustr);
         if (s != ch) break;
         if (!ch) return true;
         ustr += 2;
      } while (1);
   }
   return false;
}

dword allocateUnicodeString(const char *str) {
   int len = strlen(str);
   dword ustr = HeapBase::getHeap()->malloc(len * 2 + 2);
   dword uni = HeapBase::getHeap()->malloc(8);  //sizeof(UNICODE_STRING)

   patch_word(uni, len * 2);
   patch_word(uni + 2, len * 2 + 2);
   patch_long(uni + 4, ustr);
   for (int i = 0; i <= len; i++) {
      patch_word(ustr, *str++);
      ustr += 2;
   }
   return uni;
}

dword findPebModuleByName(char *name) {
   segment_t *s = get_segm_by_name(".peb");
   if (s) { 
      dword peb = (dword)s->startEA;
      dword pebLdr = get_long(peb + 0xC);
      dword list = pebLdr + 0xC;
      dword blink = list;
      dword flink;
      for (flink = get_long(list); 
           flink != list; 
           flink = get_long(flink)) {
         if (cmp_c_to_dbuni(name, flink + BASE_NAME_OFFSET) == 0) {
            return get_long(flink + BASE_ADDRESS_OFFSET);
         }
         blink = flink;
      }
   }
   return (dword)BADADDR;
}

void addModuleToPeb(dword handle, const char *name, bool loading) {
   segment_t *s = get_segm_by_name(".peb");
   if (s) {
      msg("adding %s (%x) to PEB\n", name, handle);
      dword peb = (dword)s->startEA;
      dword pebLdr = get_long(peb + 0xC);

      dword uni = allocateUnicodeString(name);
      msg("mod name allocated at %x\n", uni);

      //mod is the address of the LDR_MODULE that we are allocating
      dword mod = HeapBase::getHeap()->malloc(LDR_MODULE_SIZE);
      dword pe = handle + get_long(handle + 0x3C);
      msg("mod allocated at %x\n", mod);
      patch_long(mod + BASE_ADDRESS_OFFSET, handle);  //BaseAddress
      patch_long(mod + BASE_ADDRESS_OFFSET + 4, handle + get_long(pe + 0x28)); //EntryPoint
      patch_long(mod + BASE_ADDRESS_OFFSET + 8, get_long(pe + 0x50)); //SizeOfImage
//      patch_long(mod + 36, 0);  //FullDllName
      patch_long(mod + 44, get_long(uni));  //BaseDllName
      patch_long(mod + 48, get_long(uni + 4));  //BaseDllName
//      patch_long(mod + 52, 0);  //Flags
      patch_long(mod + 56, 1);  //LoadCount
//      patch_long(mod + 58, 0);  //TlsIndex
//      patch_long(mod + 60, 0);  //HashTableEntry
//      patch_long(mod + 68, 0);  //TimeDateStamp
      
      dword loadOrder = pebLdr + 0xC;
      msg("addModuleToPeb containsModule\n");
      if (containsModule(loadOrder, handle, 24)) return;
      msg("addModuleToPeb containsModule complete\n");

      dword memoryOrder = pebLdr + 0x14;
      dword initOrder = pebLdr + 0x1C;
      if (loading) {
         insertHead(initOrder, mod, 8);
      }
      else {
         msg("addModuleToPeb insertTail, initOrder\n");
         insertTail(initOrder, mod, 8);
      }
      msg("addModuleToPeb insertTail, loadOrder\n");
      insertTail(loadOrder, mod, 24);
      msg("addModuleToPeb insertTail, memoryOrder\n");
      insertInOrder(memoryOrder, mod, 16);

      msg("module added %s (%x) to PEB\n", name, handle);
   }
}

void addModuleToPeb(HandleNode *hn, bool loading, dword uni) {
   segment_t *s = get_segm_by_name(".peb");
   if (s) {
      msg("adding %s (%x) to PEB\n", hn->moduleName, hn->handle);
      dword peb = (dword)s->startEA;
      dword pebLdr = get_long(peb + 0xC);

      if (uni == 0) {
         uni = allocateUnicodeString(hn->moduleName);
      }
      msg("mod name allocated at %x\n", uni);

      //mod is the address of the LDR_MODULE that we are allocating
      dword mod = HeapBase::getHeap()->malloc(LDR_MODULE_SIZE);

      dword pe = hn->handle + get_long(hn->handle + 0x3C);
      msg("mod allocated at %x\n", mod);
      patch_long(mod + BASE_ADDRESS_OFFSET, hn->handle);  //BaseAddress
      patch_long(mod + BASE_ADDRESS_OFFSET + 4, hn->handle + get_long(pe + 0x28)); //EntryPoint
      patch_long(mod + BASE_ADDRESS_OFFSET + 8, get_long(pe + 0x50)); //SizeOfImage
//      patch_long(mod + 36, 0);  //FullDllName
      patch_long(mod + 44, get_long(uni));  //BaseDllName
      patch_long(mod + 48, get_long(uni + 4));  //BaseDllName
//      patch_long(mod + 52, 0);  //Flags
      patch_long(mod + 56, 1);  //LoadCount
//      patch_long(mod + 58, 0);  //TlsIndex
//      patch_long(mod + 60, 0);  //HashTableEntry
//      patch_long(mod + 68, 0);  //TimeDateStamp
      
      dword loadOrder = pebLdr + 0xC;
      msg("addModuleToPeb containsModule\n");
      if (containsModule(loadOrder, hn->handle, 24)) return;
      msg("addModuleToPeb containsModule complete\n");

      dword memoryOrder = pebLdr + 0x14;
      dword initOrder = pebLdr + 0x1C;
      if (loading) {
         insertHead(initOrder, mod, 8);
      }
      else {
         msg("addModuleToPeb insertTail, initOrder\n");
         insertTail(initOrder, mod, 8);
      }
      msg("addModuleToPeb insertTail, loadOrder\n");
      insertTail(loadOrder, mod, 24);
      msg("addModuleToPeb insertTail, memoryOrder\n");
      insertInOrder(memoryOrder, mod, 16);

      msg("module added %s (%x) to PEB\n", hn->moduleName, hn->handle);
   }
}

static void saveString(int which, char *str) {
#ifdef __IDP__   
   //only do something if we are in a plugin
   x86emu_node.supset(which, str);
#endif
}

static int loadString(int which, char *dir, int len) {
#ifdef __IDP__
   //only do something if we are in a plugin
   if (len) {
      *dir = 0;
   }
   return x86emu_node.supstr(which, dir, len);
#else
   return -1;
#endif
}

static void saveDllDir(char *dir) {
   saveString(SYS_DLL_DIR, dir);
}

static int getSavedDllDir(char *dir, int len) {
   //only do something if we are in a plugin
   return loadString(SYS_DLL_DIR, dir, len);
}

static void savelastDir(char *dir) {
   saveString(LAST_DIR, dir);
}

static int getLastDir(char *dir, int len) {
   //only do something if we are in a plugin
   return loadString(LAST_DIR, dir, len);
}

#ifndef __NT__

int GetSystemDirectory(char *dir, int size) {
   static char dllDir[512];
   if (dllDir[0] == 0) {
      char *dir = getDirectoryName("Choose System DLL Directory", dllDir, sizeof(dllDir));
      if (dir == NULL) {
         dllDir[0] = 0;
      }
   }
   int len = strlen(dllDir);
   ::qstrncpy(dir, dllDir, size);
   return len;
}

#endif

int getSystemDllDirectory(char *dir, int size) {
   int len = getSavedDllDir(dir, size);
   if (len == -1) {
      len = GetSystemDirectory(dir, size);
      if (len > 0) {
         saveDllDir(dir);
      }
   }
#ifdef DEBUG
   msg(PLUGIN_NAME": setting system dll directory to %s\n", dir);
#endif
   return len;
}

dword getHandle(HandleNode *m) {
   return m->handle;
}

dword getId(HandleNode *m) {
   return m->id;
}

HandleNode *addNewModuleNode(const char *mod, dword h, dword id) {
   HandleNode *m = (HandleNode*) calloc(1, sizeof(HandleNode));
   m->next = moduleHead;
   moduleHead = m;
   m->moduleName = _strdup(mod);
   m->handle = (dword) h;
   if (h & FAKE_HANDLE_BASE) {
      //faked module with no loaded export table
      m->maxAddr = h + 1;
   }
   else {  //good module load
      m->id = id ? id : moduleId;
      moduleId += 0x10000;

      dword pe_addr = m->handle + get_long(0x3C + m->handle);  //dos.e_lfanew
      m->maxAddr = m->handle + get_long(pe_addr + 0x18 + 0x38); //nt.OptionalHeader.SizeOfImage

      dword export_dir = m->handle + get_long(pe_addr + 0x18 + 0x60 + 0x0);  //export dir RVA
 
      m->ordinal_base = get_long(export_dir + 0x10);   //ed.Base

      m->NoF = get_long(export_dir + 0x14);  //ed.NumberOfFunctions
      m->NoN = get_long(export_dir + 0x18);  //ed.NumberOfNames

      m->eat = m->handle + get_long(export_dir + 0x1C);  //ed.AddressOfFunctions;
      m->ent = m->handle + get_long(export_dir + 0x20);  //ed.AddressOfNames;
      m->eot = m->handle + get_long(export_dir + 0x24);  //ed.AddressOfNameOrdinals;
   }
   return m;
}

HandleNode *addModule(const char *mod, bool loading, int id, bool addToPeb) {
   msg("x86emu: addModule called for %s\n", mod);
   HandleNode *m = findModuleByName(mod);
   if (m == NULL) {
      dword h = 0;
      dword len;

      char module_name[260];
      if ((id & FAKE_HANDLE_BASE) != 0) {
         h = id;
      }
      if (h == 0) {
         len = getSystemDllDirectory(module_name, sizeof(module_name));
         module_name[len++] = DIR_SEP;
         module_name[len] = 0;
         ::qstrncat(module_name, mod, sizeof(module_name));
         FILE *f = fopen(module_name, "rb");
         if (f == NULL) {   //try it in lower case
            for (int i = len; module_name[i]; i++) {
               module_name[i] = tolower(module_name[i]);
            }
            f = fopen(module_name, "rb");
         }
         if (f == NULL) {
            int load = R_YES;
            load = askbuttons_c("Yes", "No", "Fake it", 1, "Could not locate %s. Locate it now?", mod);
            if (load == R_YES) {
               char title[128];
               char lastDir[260];
               getLastDir(lastDir, sizeof(lastDir));
               ::qstrncpy(module_name, mod, sizeof(module_name));
#ifndef __QT__
               const char *filter = "All (*.*)\0*.*\0";
#else
               const char *filter = "All (*.*)";
#endif
               ::qsnprintf(title, sizeof(title), "Open %s", mod);
               char *fname = getOpenFileName(title, module_name, sizeof(module_name), filter, lastDir);
               if (fname) {
                  f = fopen(fname, "rb");
                  char *end = strrchr(module_name, DIR_SEP);
                  if (end) {
                     *end = 0;
                     savelastDir(module_name);
#ifdef DEBUG
                     msg(PLUGIN_NAME": saved directory %s\n", module_name);
#endif
                  }
               }
               else {
                  //change to no or fake it option at this point?
               }
            }
         }
         if (f) {
            h = loadIntoIdb(f);
            if (h == 0xFFFFFFFF) h = 0;
            fclose(f);
         }
         if (h == 0) {
            warning("Failure loading %s, faking it.", mod);
            h = FAKE_HANDLE_BASE + moduleId;
            moduleId += 0x10000;
         }
      }
      m = addNewModuleNode(mod, h, id);
      if (h && addToPeb) {
         addModuleToPeb(h, mod, loading);
      }
   }
   msg("addModule returning for %s\n", mod);
   return m;
}

void freeModuleList() {
   for (HandleNode *p = moduleHead; p; moduleHead = p) {
      p = p->next;
      free(moduleHead->moduleName);
      free(moduleHead);
   }
   for (FakedImport *f = fakedImportList; f; fakedImportList = f) {
      f = f->next;
      free(fakedImportList->name);
      free(fakedImportList);
   }
   fakedImportList = NULL;
   moduleHead = NULL;
   moduleHandle = FAKE_HANDLE_BASE;
}

void loadModuleList(Buffer &b) {
//   freeModuleList();
   int n;
   b.read((char*)&n, sizeof(n));
   for (int i = 0; i < n; i++) {
      dword id, tempid;
      char *name;
      b.read((char*)&id, sizeof(id));
      tempid = id & ~FAKE_HANDLE_BASE;
      if (tempid > moduleId) moduleId = tempid + 1;
      b.readString(&name);
      if (findModuleByName(name) == NULL) {
         HandleNode *m = addModule(name, false, id);
         m->next = moduleHead;
         moduleHead = m;
      }
      free(name);
   }
}

void saveModuleList(Buffer &b) {
   int n = 0;
   for (HandleNode *p = moduleHead; p; p = p->next) n++;
   b.write((char*)&n, sizeof(n));
   for (HandleNode *m = moduleHead; m; m = m->next) {
      dword moduleId = m->id | (m->handle & FAKE_HANDLE_BASE); //set high bit of id if using fake handle
      b.write((char*)&moduleId, sizeof(moduleId));
      b.writeString(m->moduleName);
   }
}

void loadModuleData(Buffer &b) {
   freeModuleList();
   int n = 0;
   b.read((char*)&n, sizeof(n));
   for (int i = 0; i < n; i++) {
      HandleNode *m = (HandleNode*)malloc(sizeof(HandleNode));
      m->next = moduleHead;
      moduleHead = m;

      b.read((char*)&m->handle, sizeof(m->handle));
      b.read((char*)&m->id, sizeof(m->id));
      b.read((char*)&m->maxAddr, sizeof(m->maxAddr));
      b.read((char*)&m->ordinal_base, sizeof(m->ordinal_base));
      b.read((char*)&m->NoF, sizeof(m->NoF));
      b.read((char*)&m->NoN, sizeof(m->NoN));
      b.read((char*)&m->eat, sizeof(m->eat));
      b.read((char*)&m->ent, sizeof(m->ent));
      b.read((char*)&m->eot, sizeof(m->eot));
      b.readString(&m->moduleName);
      
      if (m->id > moduleId) {
         moduleId = m->id + 0x10000;
      }
   }
   b.read((char*)&n, sizeof(n));
   for (int j = 0; j < n; j++) {
      FakedImport *f = (FakedImport*)malloc(sizeof(FakedImport));
      b.read(&f->handle, sizeof(f->handle));  //module handle the lookup was performed on
      b.read(&f->addr, sizeof(f->addr));    //returned fake import address
      b.readString(&f->name);    //name assigned to this function
   }
}

void saveModuleData(Buffer &b) {
   int n = 0;
   for (HandleNode *p = moduleHead; p; p = p->next) n++;
   b.write((char*)&n, sizeof(n));
   for (HandleNode *m = moduleHead; m; m = m->next) {
      b.write((char*)&m->handle, sizeof(m->handle));
      b.write((char*)&m->id, sizeof(m->id));
      b.write((char*)&m->maxAddr, sizeof(m->maxAddr));
      b.write((char*)&m->ordinal_base, sizeof(m->ordinal_base));
      b.write((char*)&m->NoF, sizeof(m->NoF));
      b.write((char*)&m->NoN, sizeof(m->NoN));
      b.write((char*)&m->eat, sizeof(m->eat));
      b.write((char*)&m->ent, sizeof(m->ent));
      b.write((char*)&m->eot, sizeof(m->eot));
      b.writeString(m->moduleName);
   }
   //now save our FakedImport list as well
   n = 0;
   for (FakedImport *f = fakedImportList; f; f = f->next) n++;
   b.write((char*)&n, sizeof(n));
   for (FakedImport *i = fakedImportList; i; i = i->next) {
      b.write(&i->handle, sizeof(i->handle));  //module handle the lookup was performed on
      b.write(&i->addr, sizeof(i->addr));    //returned fake import address
      b.writeString(i->name);    //name assigned to this function
   }
}

/*
 * Build an ascii C string by reading directly from the database
 * until a NULL is encountered.  Returned value must be free'd
 */

char *getString(dword addr) {
   int size = 16;
   int i = 0;
   byte *str = NULL, ch;
   str = (byte*) malloc(size);
   if (addr) {
      while ((ch = get_byte(addr++)) != 0) {
         if (i == size) {
            str = (byte*)realloc(str, size + 16);
            size += 16;
         }
         if (ch == 0xFF) break;  //should be ascii, something wrong here
         str[i++] = ch;
      }
      if (i == size) {
         str = (byte*)realloc(str, size + 1);
      }
   }
   str[i] = 0;
   return (char*)str;
}

/*
 * Build an ascii C string from a wchar string by reading 
 * directly from the database
 * until a NULL is encountered.  Returned value must be free'd
 */

char *getStringW(dword addr) {
   int size = 16;
   int i = 0;
   byte *str = NULL;
   short ch;
   str = (byte*) malloc(size);
   if (addr) {
      while ((ch = get_word(addr)) != 0) {
         if (i == size) {
            str = (byte*)realloc(str, size + 16);
            size += 16;
         }
         if (ch == 0xFF) break;  //should be ascii, something wrong here
         str[i++] = (char)ch;
         addr += 2;
      }
      if (i == size) {
         str = (byte*)realloc(str, size + 1);
      }
   }
   str[i] = 0;
   return (char*)str;
}

/*
 * set the callback function to use when anything that is hooked, but
 * unemulated is called
 */
void setUnemulatedCB(unemulatedCB cb) {
   unemulated_cb = cb;
}

/*
 * This function is used for all unemulated API functions
 */
void unemulated(dword addr) {
   if (unemulated_cb) {
      HookNode *n = findHookByAddr(addr);
      (*unemulated_cb)(addr, n ? n->getName() : NULL);
   }
}

/*
   These functions emulate various API calls.  The idea is
   to invoke them after all parameters have been pushed onto the
   stack.  Each function understands its corresponding parameters
   and calling conventions and leaves the stack in the proper state
   with a result in eax.  Because these are invoked from the emulator
   no return address gets pushed onto the stack and the functions can
   get right at their parameters on top of the stack.
*/

void emu_GetCommandLineA(dword /*addr*/) {
   eax = pCmdLineA;
   if (doLogLib) {
      msg("call: GetCommandLineA() = 0x%x\n", eax);
   }
}

//*** this needs more work
//common core for GetStartupInfoX
void emu_GetStartupInfo(dword lpStartupInfo, dword pp) {
   patch_long(lpStartupInfo, 0x44);   //cb = sizeof(STARTUPINFO)

   patch_long(lpStartupInfo + 4, 0);   //lpReserved

   patch_long(lpStartupInfo + 0x20, 0);   //dwFillAttribute
   patch_word(lpStartupInfo + 0x30, 1);   //wShowWindow == SW_SHOWNORMAL
   patch_word(lpStartupInfo + 0x32, 0);   //cbReserved2
   patch_long(lpStartupInfo + 0x34, 0);   //lpReserved2

   patch_long(lpStartupInfo + 0x38, get_long(pp + 0x18));   //hStdInput
   patch_long(lpStartupInfo + 0x3C, get_long(pp + 0x1C));   //hStdOutput
   patch_long(lpStartupInfo + 0x40, get_long(pp + 0x20));   //hStdError
}

void emu_GetStartupInfoA(dword /*addr*/) {
   //this can raise an exception, but which one?
   dword lpStartupInfo = pop(SIZE_DWORD);
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pp = readDword(peb + PEB_PROCESS_PARMS);

   patch_long(lpStartupInfo + 8, get_long(pp + SIZEOF_PROCESS_PARAMETERS + 4));   //DesktopInfo
   patch_long(lpStartupInfo + 12, get_long(pp + SIZEOF_PROCESS_PARAMETERS));   //WindowTitle

   emu_GetStartupInfo(lpStartupInfo, pp);
   if (doLogLib) {
      msg("call: GetStartupInfoA(0x%x)\n", lpStartupInfo);
   }
}

void emu_GetStartupInfoW(dword /*addr*/) {
   dword lpStartupInfo = pop(SIZE_DWORD);
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pp = readDword(peb + PEB_PROCESS_PARMS);

   patch_long(lpStartupInfo + 8, get_long(pp + 0x7C));   //DesktopInfo
   patch_long(lpStartupInfo + 12, get_long(pp + 0x74));   //WindowTitle
   emu_GetStartupInfo(lpStartupInfo, pp);
   if (doLogLib) {
      msg("call: GetStartupInfoW(0x%x)\n", lpStartupInfo);
   }
}

void emu_GetLocaleInfoA(dword /*addr*/) {
   dword Locale = pop(SIZE_DWORD);
   dword LCType = pop(SIZE_DWORD);
   dword lpLCData = pop(SIZE_DWORD);
   dword cchData = pop(SIZE_DWORD);

   eax = 1;
   switch (Locale) {
      case 0:
      case 1033:
      case 0x400: //LOCALE_USER_DEFAULT
      case 0x800: //LOCALE_SYSTEM_DEFAULT
         break;   
      default:
         eax = 0;
         setThreadError(87);   //ERROR_INVALID_PARAMETER
         break;
   }
   if (eax) {  //no error yet
      switch (LCType) {
         case 0x1004:  //LOCALE_IDEFAULTANSICODEPAGE
            //hard coded to code page 1252
            if (cchData == 0) {
               eax = 5; //"1252"
            }
            else if (lpLCData == 0 || cchData < 5) {
               eax = 0;   
               setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
            }
            else {
               put_many_bytes(lpLCData, "1252", 5);
            }
            break;
         case 0x1001:  //LOCALE_SENGLANGUAGE
            //hard coded to English
            if (cchData == 0) {
               eax = 8; //"English"
            }
            else if (lpLCData == 0 || cchData < 8) {
               eax = 0;   
               setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
            }
            else {
               put_many_bytes(lpLCData, "English", 8);
            }
            break;
         case 0x1002:  //LOCALE_SENGCOUNTRY
            //hard coded to "United States"
            if (cchData == 0) {
               eax = 14; //"United States"
            }
            else if (lpLCData == 0 || cchData < 14) {
               eax = 0;
               setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
            }
            else {
               put_many_bytes(lpLCData, "United States", 14);
            }
            break;
         default:
            eax = 0;
            setThreadError(87);   //ERROR_INVALID_PARAMETER
            break;
      }
   }
   
   if (doLogLib) {
      msg("call: GetLocaleInfoA(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
                  Locale, LCType, lpLCData, cchData, eax);
   }
}

void emu_GetLocaleInfoW(dword /*addr*/) {
   dword Locale = pop(SIZE_DWORD);
   dword LCType = pop(SIZE_DWORD);
   dword lpLCData = pop(SIZE_DWORD);
   dword cchData = pop(SIZE_DWORD);

   eax = 1;
   switch (Locale) {
      case 0:
      case 1033:
      case 0x400: //LOCALE_USER_DEFAULT
      case 0x800: //LOCALE_SYSTEM_DEFAULT
         break;   
      default:
         eax = 0;
         setThreadError(87);   //ERROR_INVALID_PARAMETER
         break;
   }
   if (eax) {  //no error yet
      switch (LCType) {
         case 0x1004:  //LOCALE_IDEFAULTANSICODEPAGE
            //hard coded to code page 1252
            if (cchData == 0) {
               eax = 5; //"1252"
            }
            else if (lpLCData == 0 || cchData < 5) {
               eax = 0;   
               setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
            }
            else {
               put_many_bytes(lpLCData, "\x31\x00\x32\x00\x35\x00\x32\x00\x00\x00", 10);
            }
            break;
         case 0x1001:  //LOCALE_SENGLANGUAGE
            //hard coded to English
            if (cchData == 0) {
               eax = 8; //"English"
            }
            else if (lpLCData == 0 || cchData < 8) {
               eax = 0;   
               setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
            }
            else {
               put_many_bytes(lpLCData, "\x45\x00\x6e\x00\x67\x00\x6c\x00\x69\x00\x73\x00\x68\x00\x00\x00", 16);
            }
            break;
         case 0x1002:  //LOCALE_SENGCOUNTRY
            //hard coded to "United States"
            if (cchData == 0) {
               eax = 14; //"United States"
            }
            else if (lpLCData == 0 || cchData < 14) {
               eax = 0;
               setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
            }
            else {
               put_many_bytes(lpLCData, "\x55\x00\x6e\x00\x69\x00\x74\x00\x65\x00\x64\x00\x20\x00\x53\x00\x74\x00\x61\x00\x74\x00\x65\x00\x73\x00\x00\x00", 28);
            }
            break;
         default:
            eax = 0;
            setThreadError(87);   //ERROR_INVALID_PARAMETER
            break;
      }
   }

   if (doLogLib) {
      msg("call: GetLocaleInfoW(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
                  Locale, LCType, lpLCData, cchData, eax);
   }
}

static char wcmbdata[] =
   "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
   "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
   "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
   "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
   "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
   "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
   "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
   "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x3f"
   "\x81\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x8d\x3f\x8f\x90"
   "\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x9d\x3f\x3f\xa0"
   "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
   "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
   "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
   "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
   "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
   "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

void emu_WideCharToMultiByte(dword /*addr*/) {
   dword CodePage = pop(SIZE_DWORD);
   dword dwFlags = pop(SIZE_DWORD);   //*** update, don't ignore this
   dword lpWideCharStr = pop(SIZE_DWORD);
   dword cchWideChar = pop(SIZE_DWORD);
   dword lpMultiByteStr = pop(SIZE_DWORD);
   dword cbMultiByte = pop(SIZE_DWORD);
   dword lpDefaultChar = pop(SIZE_DWORD);  //*** update, don't ignore this
   dword lpUsedDefaultChar = pop(SIZE_DWORD);  //*** update, don't ignore this

   if (lpWideCharStr == lpMultiByteStr || cchWideChar == 0) {
      eax = 0;
      setThreadError(87);   //ERROR_INVALID_PARAMETER
   }
   else {
      eax = 1;
      switch (CodePage) {
         case 0:
         case 1:
         case 437:  //(US)
         case 0x4e4:  //1252 == Latin I
         case 0xfde9: //CP_UTF8
            if (cchWideChar == 0xffffffff) {
               cchWideChar++;
               while (get_word(lpWideCharStr + cchWideChar * 2) != 0) {
                  cchWideChar++;
               }
               cchWideChar++;
            }
            if (cbMultiByte == 0) {
               eax = cchWideChar;
            }
            else {
               dword i;
               for (i = 0; i < cchWideChar; i++) {
                  unsigned short ch = get_word(lpWideCharStr + i * 2);
                  if (ch > 255) {
                     //*** no idea whether this is generally correct
                     ch = '?';
                  }
                  else {
                     ch = wcmbdata[ch];
                  }
                  patch_byte(lpMultiByteStr + i, ch);
               }
               eax = i;
            }
            break;
         default:
            eax = 0;
            setThreadError(87);   //ERROR_INVALID_PARAMETER
            break;
      }
   }   
   if (doLogLib) {
      msg("call: WideCharToMultiByte(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
                  CodePage, dwFlags, lpWideCharStr, cchWideChar, 
                  lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar, eax);
   }
}

static const unsigned short *mbwcdata = (const unsigned short *)
   "\x00\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00"
   "\x09\x00\x0a\x00\x0b\x00\x0c\x00\x0d\x00\x0e\x00\x0f\x00\x10\x00"
   "\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00"
   "\x19\x00\x1a\x00\x1b\x00\x1c\x00\x1d\x00\x1e\x00\x1f\x00\x20\x00"
   "\x21\x00\x22\x00\x23\x00\x24\x00\x25\x00\x26\x00\x27\x00\x28\x00"
   "\x29\x00\x2a\x00\x2b\x00\x2c\x00\x2d\x00\x2e\x00\x2f\x00\x30\x00"
   "\x31\x00\x32\x00\x33\x00\x34\x00\x35\x00\x36\x00\x37\x00\x38\x00"
   "\x39\x00\x3a\x00\x3b\x00\x3c\x00\x3d\x00\x3e\x00\x3f\x00\x40\x00"
   "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x48\x00"
   "\x49\x00\x4a\x00\x4b\x00\x4c\x00\x4d\x00\x4e\x00\x4f\x00\x50\x00"
   "\x51\x00\x52\x00\x53\x00\x54\x00\x55\x00\x56\x00\x57\x00\x58\x00"
   "\x59\x00\x5a\x00\x5b\x00\x5c\x00\x5d\x00\x5e\x00\x5f\x00\x60\x00"
   "\x61\x00\x62\x00\x63\x00\x64\x00\x65\x00\x66\x00\x67\x00\x68\x00"
   "\x69\x00\x6a\x00\x6b\x00\x6c\x00\x6d\x00\x6e\x00\x6f\x00\x70\x00"
   "\x71\x00\x72\x00\x73\x00\x74\x00\x75\x00\x76\x00\x77\x00\x78\x00"
   "\x79\x00\x7a\x00\x7b\x00\x7c\x00\x7d\x00\x7e\x00\x7f\x00\xac\x20"
   "\x81\x00\x1a\x20\x92\x01\x1e\x20\x26\x20\x20\x20\x21\x20\xc6\x02"
   "\x30\x20\x60\x01\x39\x20\x52\x01\x8d\x00\x7d\x01\x8f\x00\x90\x00"
   "\x18\x20\x19\x20\x1c\x20\x1d\x20\x22\x20\x13\x20\x14\x20\xdc\x02"
   "\x22\x21\x61\x01\x3a\x20\x53\x01\x9d\x00\x7e\x01\x78\x01\xa0\x00"
   "\xa1\x00\xa2\x00\xa3\x00\xa4\x00\xa5\x00\xa6\x00\xa7\x00\xa8\x00"
   "\xa9\x00\xaa\x00\xab\x00\xac\x00\xad\x00\xae\x00\xaf\x00\xb0\x00"
   "\xb1\x00\xb2\x00\xb3\x00\xb4\x00\xb5\x00\xb6\x00\xb7\x00\xb8\x00"
   "\xb9\x00\xba\x00\xbb\x00\xbc\x00\xbd\x00\xbe\x00\xbf\x00\xc0\x00"
   "\xc1\x00\xc2\x00\xc3\x00\xc4\x00\xc5\x00\xc6\x00\xc7\x00\xc8\x00"
   "\xc9\x00\xca\x00\xcb\x00\xcc\x00\xcd\x00\xce\x00\xcf\x00\xd0\x00"
   "\xd1\x00\xd2\x00\xd3\x00\xd4\x00\xd5\x00\xd6\x00\xd7\x00\xd8\x00"
   "\xd9\x00\xda\x00\xdb\x00\xdc\x00\xdd\x00\xde\x00\xdf\x00\xe0\x00"
   "\xe1\x00\xe2\x00\xe3\x00\xe4\x00\xe5\x00\xe6\x00\xe7\x00\xe8\x00"
   "\xe9\x00\xea\x00\xeb\x00\xec\x00\xed\x00\xee\x00\xef\x00\xf0\x00"
   "\xf1\x00\xf2\x00\xf3\x00\xf4\x00\xf5\x00\xf6\x00\xf7\x00\xf8\x00"
   "\xf9\x00\xfa\x00\xfb\x00\xfc\x00\xfd\x00\xfe\x00\xff\x00";
   
void emu_MultiByteToWideChar(dword /*addr*/) {
   dword CodePage = pop(SIZE_DWORD);
   dword dwFlags = pop(SIZE_DWORD);
   dword lpMultiByteStr = pop(SIZE_DWORD);
   dword cbMultiByte = pop(SIZE_DWORD);
   dword lpWideCharStr = pop(SIZE_DWORD);
   dword cchWideChar = pop(SIZE_DWORD);

   if (lpWideCharStr == lpMultiByteStr || cbMultiByte == 0) {
      eax = 0;
      setThreadError(87);   //ERROR_INVALID_PARAMETER
   }
   else {
      eax = 1;
      switch (CodePage) {
         case 0:
         case 1:
         case 437:  //(US)
         case 0x4e4:  //1252 == Latin I
         case 0xfde9: //CP_UTF8
            if (cbMultiByte == 0xffffffff) {
               cbMultiByte++;
               while (get_byte(lpMultiByteStr + cbMultiByte) != 0) {
                  cbMultiByte++;
               }
               cbMultiByte++;
            }
            if (cchWideChar == 0) {
               eax = cbMultiByte;
            }
            else {
               dword i;
               for (i = 0; i < cbMultiByte; i++) {
                  unsigned short ch = get_byte(lpMultiByteStr + i);
                  ch = mbwcdata[ch];
                  patch_word(lpWideCharStr + i * 2, ch);
               }
               eax = i;
            }
            break;
         default:
            eax = 0;
            setThreadError(87);   //ERROR_INVALID_PARAMETER
            break;
      }
   }   

   if (doLogLib) {
      msg("call: MultiByteToWideChar(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", 
                 CodePage, dwFlags, lpMultiByteStr, 
                 cbMultiByte, lpWideCharStr, cchWideChar, eax);
   }
}

static const unsigned short *typeW = (const unsigned short *)
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02"
   "\x68\x02\x28\x02\x28\x02\x28\x02\x28\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x48\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x84\x02"
   "\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02"
   "\x84\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x81\x03\x81\x03\x81\x03\x81\x03\x81\x03\x81\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x82\x03\x82\x03\x82\x03\x82\x03\x82\x03\x82\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x10\x02\x10\x02\x10\x02\x10\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x28\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x48\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x10\x02\x12\x03\x10\x02\x10\x02\x30\x02\x10\x02\x10\x02\x10\x02"
   "\x10\x02\x14\x02\x14\x02\x10\x02\x12\x03\x10\x02\x10\x02\x10\x02"
   "\x14\x02\x12\x03\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x10\x02\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x10\x02\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03";
   
void emu_GetStringTypeW(dword /*addr*/) {
   dword dwInfoType = pop(SIZE_DWORD);
   dword lpSrcStr = pop(SIZE_DWORD);
   int cchSrc = (int)pop(SIZE_DWORD);
   dword lpCharType = pop(SIZE_DWORD);

   if (dwInfoType != 1) {
      //*** handle additional dwInfoType values
      eax = 0;
      setThreadError(87);   //ERROR_INVALID_PARAMETER
   }
   else {
      unsigned short ch;
      eax = 1;
      if (cchSrc < 0) {
         int i = 0;
         do {
            ch = get_word(lpSrcStr + i * 2);
            patch_word(lpCharType + i * 2, ch < 256 ? typeW[ch] : 0); //0 is certainly not correct default here
            i++;
         } while (ch != 0);
      }
      else {
         for (int i = 0; i < cchSrc; i++) {
            ch = get_word(lpSrcStr + i * 2);
            patch_word(lpCharType + i * 2, ch < 256 ? typeW[ch] : 0); //0 is certainly not correct default here
         }
      }
   }
   
   if (doLogLib) {
      msg("call: GetStringTypeW(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", 
                 dwInfoType, lpSrcStr, cchSrc, lpCharType, eax);
   }
}

static const unsigned short *typeA = (const unsigned short *)
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02"
   "\x68\x02\x28\x02\x28\x02\x28\x02\x28\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02"
   "\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x20\x02\x48\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x84\x02"
   "\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02\x84\x02"
   "\x84\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x81\x03\x81\x03\x81\x03\x81\x03\x81\x03\x81\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x82\x03\x82\x03\x82\x03\x82\x03\x82\x03\x82\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x10\x02\x10\x02\x10\x02\x10\x02\x20\x02\x00\x02"
   "\x20\x02\x10\x02\x02\x03\x10\x02\x10\x02\x10\x02\x10\x02\x00\x02"
   "\x10\x02\x01\x03\x10\x02\x01\x03\x20\x02\x01\x03\x20\x02\x20\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x00\x02"
   "\x00\x02\x02\x03\x10\x02\x02\x03\x20\x02\x02\x03\x01\x03\x48\x02"
   "\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02"
   "\x10\x02\x12\x03\x10\x02\x10\x02\x30\x02\x10\x02\x10\x02\x10\x02"
   "\x10\x02\x14\x02\x14\x02\x10\x02\x12\x03\x10\x02\x10\x02\x10\x02"
   "\x14\x02\x12\x03\x10\x02\x10\x02\x10\x02\x10\x02\x10\x02\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x10\x02\x01\x03"
   "\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x01\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x10\x02\x02\x03"
   "\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03\x02\x03";
   
void emu_GetStringTypeA(dword /*addr*/) {
   dword Locale = pop(SIZE_DWORD);
   dword dwInfoType = pop(SIZE_DWORD);
   dword lpSrcStr = pop(SIZE_DWORD);
   int cchSrc = (int)pop(SIZE_DWORD);
   dword lpCharType = pop(SIZE_DWORD);

   if (dwInfoType != 1) {
      //*** handle additional dwInfoType values
      eax = 0;
      setThreadError(87);   //ERROR_INVALID_PARAMETER
   }
   else {
      eax = 1;
      switch (Locale) {
         case 0x0409: { //1033
            unsigned char ch;
            if (cchSrc < 0) {
               int i = 0;
               do {
                  ch = get_byte(lpSrcStr + i);
                  patch_word(lpCharType + i * 2, typeA[ch]);
                  i++;
               } while (ch != 0);
            }
            else {
               for (int i = 0; i < cchSrc; i++) {
                  patch_word(lpCharType + i * 2, typeA[get_byte(lpSrcStr + i)]);
               }
            }
            break;
         }
         default:
            eax = 0;
            setThreadError(87);   //ERROR_INVALID_PARAMETER
            break;
      }
   }
   if (doLogLib) {
      msg("call: GetStringTypeA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", 
                 Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType, eax);
   }
}

//*** need implementations for things other than lower and upper
void emu_LCMapStringW(dword /*addr*/) {
   dword Locale = pop(SIZE_DWORD);
   dword dwMapFlags = pop(SIZE_DWORD);
   dword lpSrcStr = pop(SIZE_DWORD);
   dword cchSrc = pop(SIZE_DWORD);
   dword lpDestStr = pop(SIZE_DWORD);
   dword cchDest = pop(SIZE_DWORD);

   eax = 1;
   
   if (lpSrcStr == 0 || cchSrc == 0) {
      eax = 0;
      setThreadError(87);   //ERROR_INVALID_PARAMETER
   }
   else {
      if (cchSrc < 0) {
         unsigned short ch;
         cchSrc = 0;
         do {
            ch = get_word(lpSrcStr + cchSrc);
            cchSrc++;
         } while (ch != 0);
      }
      if (cchDest && (cchDest < cchSrc)) {
         eax = 0;
         setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
      }
      else {
         switch (dwMapFlags) {
            case 0x100: //LCMAP_LOWERCASE
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else {
                  for (dword i = 0; i < cchSrc; i++) {
                     patch_word(lpDestStr + i * 2, tolower(get_word(lpSrcStr + i * 2)));
                  }
               }
               break;
            case 0x200: //LCMAP_UPPERCASE
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else {
                  for (dword i = 0; i < cchSrc; i++) {
                     patch_word(lpDestStr + i * 2, toupper(get_word(lpSrcStr + i * 2)));
                  }
               }
               break;
            case 0x400: //LCMAP_SORTKEY
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else if (lpSrcStr == lpDestStr) {
                  eax = 0;
                  setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
               }
               break;
            case 0x800: //LCMAP_BYTEREV
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else if (lpSrcStr == lpDestStr) {
                  eax = 0;
                  setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
               }
               break;
            case 0x100000: //LCMAP_HIRAGANA
               //break;
            case 0x200000: //LCMAP_KATAKANA
               //break;
            case 0x400000: //LCMAP_HALFWIDTH
               //break;
            case 0x800000: //LCMAP_FULLWIDTH
               //break;
            case 0x1000000: //LCMAP_LINGUISTIC_CASING
               //break;
            case 0x2000000: //LCMAP_SIMPLIFIED_CHINESE
               break;
            case 0x4000000: //LCMAP_TRADITIONAL_CHINESE
               //break;
            default:
               eax = 0;
               setThreadError(87);   //ERROR_INVALID_PARAMETER
               break;         
         }
      }
   }

   if (doLogLib) {
      msg("call: LCMapStringW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", 
                 Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, eax);
   }
}

//*** need implementations for things other than lower and upper
void emu_LCMapStringA(dword /*addr*/) {
   dword Locale = pop(SIZE_DWORD);
   dword dwMapFlags = pop(SIZE_DWORD);
   dword lpSrcStr = pop(SIZE_DWORD);
   dword cchSrc = pop(SIZE_DWORD);
   dword lpDestStr = pop(SIZE_DWORD);
   dword cchDest = pop(SIZE_DWORD);

   eax = 1;
   
   if (lpSrcStr == 0 || cchSrc == 0) {
      eax = 0;
      setThreadError(87);   //ERROR_INVALID_PARAMETER
   }
   else {
      if (cchSrc < 0) {
         unsigned char ch;
         cchSrc = 0;
         do {
            ch = get_byte(lpSrcStr + cchSrc);
            cchSrc++;
         } while (ch != 0);
      }
      if (cchDest && (cchDest < cchSrc)) {
         eax = 0;
         setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
      }
      else {
         switch (dwMapFlags) {
            case 0x100: //LCMAP_LOWERCASE
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else {
                  for (dword i = 0; i < cchSrc; i++) {
                     patch_byte(lpDestStr + i, tolower(get_byte(lpSrcStr + i)));
                  }
               }
               break;
            case 0x200: //LCMAP_UPPERCASE
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else {
                  for (dword i = 0; i < cchSrc; i++) {
                     patch_byte(lpDestStr + i, toupper(get_byte(lpSrcStr + i)));
                  }
               }
               break;
            case 0x400: //LCMAP_SORTKEY
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else if (lpSrcStr == lpDestStr) {
                  eax = 0;
                  setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
               }
               break;
            case 0x800: //LCMAP_BYTEREV
               if (cchDest == 0) {
                  eax = cchSrc;
               }
               else if (lpSrcStr == lpDestStr) {
                  eax = 0;
                  setThreadError(122);   //ERROR_INSUFFICIENT_BUFFER
               }
               break;
            case 0x100000: //LCMAP_HIRAGANA
               //break;
            case 0x200000: //LCMAP_KATAKANA
               //break;
            case 0x400000: //LCMAP_HALFWIDTH
               //break;
            case 0x800000: //LCMAP_FULLWIDTH
               //break;
            case 0x1000000: //LCMAP_LINGUISTIC_CASING
               //break;
            case 0x2000000: //LCMAP_SIMPLIFIED_CHINESE
               break;
            case 0x4000000: //LCMAP_TRADITIONAL_CHINESE
               //break;
            default:
               eax = 0;
               setThreadError(87);   //ERROR_INVALID_PARAMETER
               break;         
         }
      }
   }
   if (doLogLib) {
      msg("call: LCMapStringA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
                 Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, eax);
   }
}

//*** need more code pages
void emu_GetCPInfo(dword /*addr*/) {
   dword CodePage = pop(SIZE_DWORD);
   dword lpCPInfo = pop(SIZE_DWORD);
   
   eax = 1;
   switch (CodePage) {
      case 0:
      case 1:
      case 437:  //(US)
      case 0x4e4:  //1252 == Latin I
         patch_long(lpCPInfo, 1);
         patch_word(lpCPInfo + 4, '?');
         patch_word(lpCPInfo + 6, 0);
         patch_long(lpCPInfo + 8, 0);
         patch_long(lpCPInfo + 12, 0);
         patch_long(lpCPInfo + 16, 0);
         break;
      default:
         eax = 0;
         setThreadError(87);   //ERROR_INVALID_PARAMETER
         break;
   }
   
   if (doLogLib) {
      msg("call: GetCPInfo(0x%x, 0x%x) = 0x%x\n", CodePage, lpCPInfo, eax);
   }
}

static const char windowsDir[] = "C:\\Windows";

//*** make the return value here configurable
void emu_GetWindowsDirectoryA(dword /*addr*/) {
   dword lpBuffer = pop(SIZE_DWORD);
   dword uSize = pop(SIZE_DWORD);

   if (uSize < sizeof(windowsDir)) {
      eax = sizeof(windowsDir);
   }
   else {
      eax = sizeof(windowsDir) - 1;
      for (int i = 0; i < sizeof(windowsDir); i++) {
         patch_byte(lpBuffer + i, windowsDir[i]);
      }
   }
   
   if (doLogLib) {
      msg("call: GetWindowsDirectoryA(0x%x, 0x%x) = 0x%x\n", lpBuffer, uSize, eax);
   }
}

//*** make the return value here configurable
void emu_GetWindowsDirectoryW(dword /*addr*/) {
   dword lpBuffer = pop(SIZE_DWORD);
   dword uSize = pop(SIZE_DWORD);

   if (uSize < sizeof(windowsDir)) {
      eax = sizeof(windowsDir);
   }
   else {
      eax = sizeof(windowsDir) - 1;
      for (int i = 0; i < sizeof(windowsDir); i++) {
         patch_word(lpBuffer + i * 2, windowsDir[i]);
      }
   }

   if (doLogLib) {
      msg("call: GetWindowsDirectoryW(0x%x, 0x%x) = 0x%x\n", lpBuffer, uSize, eax);
   }
}

static const char systemDir[] = "C:\\Windows\\System32";

//*** make the return value here configurable
void emu_GetSystemDirectoryA(dword /*addr*/) {
   dword lpBuffer = pop(SIZE_DWORD);
   dword uSize = pop(SIZE_DWORD);

   if (uSize < sizeof(systemDir)) {
      eax = sizeof(systemDir);
   }
   else {
      eax = sizeof(systemDir) - 1;
      for (int i = 0; i < sizeof(systemDir); i++) {
         patch_byte(lpBuffer + i, systemDir[i]);
      }
   }
   
   if (doLogLib) {
      msg("call: GetSystemDirectoryA(0x%x, 0x%x) = 0x%x\n", lpBuffer, uSize, eax);
   }
}

//*** make the return value here configurable
void emu_GetSystemDirectoryW(dword /*addr*/) {
   dword lpBuffer = pop(SIZE_DWORD);
   dword uSize = pop(SIZE_DWORD);

   if (uSize < sizeof(systemDir)) {
      eax = sizeof(systemDir);
   }
   else {
      eax = sizeof(systemDir) - 1;
      for (int i = 0; i < sizeof(systemDir); i++) {
         patch_word(lpBuffer + i * 2, systemDir[i]);
      }
   }

   if (doLogLib) {
      msg("call: GetSystemDirectoryW(0x%x, 0x%x) = 0x%x\n", lpBuffer, uSize, eax);
   }
}

void emu_GetStdHandle(dword /*addr*/) {
   dword handle = pop(SIZE_DWORD);
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pp = readDword(peb + PEB_PROCESS_PARMS);
   switch (handle) {
      case 0xfffffff6:   //STD_INPUT_HANDLE
         eax = get_long(pp + 0x18);
         break;
      case 0xfffffff5:   //STD_OUTPUT_HANDLE
         eax = get_long(pp + 0x1C);
         break;
      case 0xfffffff4:   //STD_ERROR_HANDLE
         eax = get_long(pp + 0x20);
         break;
      default:
         eax = 0xffffffff;
         //setThreadError(0xc0000017);   //what error?
         break;
   }
   if (doLogLib) {
      msg("call: GetStdHandle(0x%x) = 0x%x\n", handle, eax);
   }
}

void emu_GetCommandLineW(dword /*addr*/) {
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pp = readDword(peb + PEB_PROCESS_PARMS);
   eax = readDword(pp + PARMS_CMD_LINE + 4);
   if (doLogLib) {
      msg("call: GetCommandLineW() = 0x%x\n", eax);
   }
}

void emu_FreeEnvironmentStringsA(dword /*addr*/) {
   dword env = pop(SIZE_DWORD);
   eax = HeapBase::getHeap()->free(env) ? 1 : 0;
   if (doLogLib) {
      msg("call: FreeEnvironmentStringsA(0x%x) = %d\n", env, eax);
   }
}

void emu_FreeEnvironmentStringsW(dword /*addr*/) {
   dword env = pop(SIZE_DWORD);
   eax = 1;
   if (doLogLib) {
      msg("call: FreeEnvironmentStringsW(0x%x) = %d\n", env, eax);
   }
}

void emu_GetEnvironmentStringsA(dword /*addr*/) {
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pp = readDword(peb + PEB_PROCESS_PARMS);
   dword wenv = readDword(pp + PARMS_ENV_PTR);
   unsigned int len = 0;
   while (1) {
      while (get_word(wenv + len * 2)) {
         len++;
      }
      if (get_word(wenv + len * 2)) {
         len++;
         break;
      }      
   }
   eax = HeapBase::getHeap()->malloc(len);
   for (unsigned int i = 0; i < len; i++) {
      patch_byte(eax + i, get_word(wenv + i * 2));
   }
   if (doLogLib) {
      msg("call: GetEnvironmentStringsA() = 0x%x\n", eax);
   }
}

void emu_GetEnvironmentStringsW(dword /*addr*/) {
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pp = readDword(peb + PEB_PROCESS_PARMS);
   eax = readDword(pp + PARMS_ENV_PTR);
   if (doLogLib) {
      msg("call: GetEnvironmentStringsW() = 0x%x\n", eax);
   }
}

void emu_FlsAlloc(dword addr) {
   //for now this forwards to TlsAlloc
   dword arg = pop(SIZE_DWORD);  //discard callback func argument
   bool bak = doLogLib;
   doLogLib = false;
   emu_TlsAlloc(addr);
   if (bak) {
      msg("call: FlsAlloc(0x%x) = 0x%x\n", arg, eax);
      doLogLib = true;
   }
}

void emu_TlsAlloc(dword /*addr*/) {
   //return is dword index of newly allocated value which is initialized to zero
   //fail value is TLS_OUT_OF_INDEXES
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword bitmapPtr = readDword(peb + PEB_TLS_BITMAP);
   for (int i = 0; i < 2; i++) {
      dword bits = readDword(bitmapPtr);
      dword bit = 1;
      for (int j = 0; j < 32; j++) {
         if ((bits & bit) == 0) {
            bits |= bit;
            writeDword(bitmapPtr, bits);
            eax = i * 32 + j;
            writeDword(fsBase + TEB_TLS_ARRAY + eax * 4, 0);
            if (doLogLib) {
               msg("call: TlsAlloc() = 0x%x\n", eax);
            }
            return;
         }
         bit <<= 1;
      }
      bitmapPtr += 4;
   }
   bitmapPtr = readDword(peb + PEB_TLS_EXP_BITMAP);

   dword exp = readDword(fsBase + TEB_TLS_EXPANSION);
   if (exp == 0) {
      exp = HeapBase::getHeap()->calloc(0x1000, 1);
      writeDword(fsBase + TEB_TLS_EXPANSION, exp);
   }
   if (exp == 0) {
      //error code is STATUS_NO_MEMORY == 0xc0000017
      //no memory available to allocate expansion page
      eax = 0;
      setThreadError(0xc0000017);
      if (doLogLib) {
         msg("call: TlsAlloc() = 0\n");
      }
      return;
   }

   for (int i = 0; i < 32; i++) {
      dword bits = readDword(bitmapPtr);
      dword bit = 1;
      for (int j = 0; j < 32; j++) {
         if ((bits & bit) == 0) {
            bits |= bit;
            writeDword(bitmapPtr, bits);
            eax = i * 32 + j;
            writeDword(exp + eax * 4, 0);
            eax += 64;
            if (doLogLib) {
               msg("call: TlsAlloc() = 0x%x\n", eax);
            }
            return;
         }
         bit <<= 1;
      }
      bitmapPtr += 4;
   }
   //error code is STATUS_NO_MEMORY == 0xc0000017
   eax = 0xffffffff;   //TLS_OUT_OF_INDEXES
   setThreadError(0xc0000017);
   if (doLogLib) {
      msg("call: TlsAlloc() = 0xffffffff\n");
   }
}

void emu_TlsFree(dword /*addr*/) {
   //return is BOOL 0 - fail, 1 - success
   dword dwTlsIndex = pop(SIZE_DWORD);

   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword bword = dwTlsIndex >> 5;
   dword bbit = 1 << (dwTlsIndex & 0x1F);
   if (bword < 2) {
      dword bitmapPtr = readDword(peb + PEB_TLS_BITMAP);
      dword bits = readDword(bitmapPtr + bword * 4);
      if (bits & bbit) {
         bits &= ~bbit;
         writeDword(bitmapPtr + bword * 4, bits);
         eax = 1;
      }
      else {
         //index was not allocated
         eax = 0;
      }
   }
   else if (bword < 34) {
      bword -= 2;
      dword bitmapPtr = readDword(peb + PEB_TLS_EXP_BITMAP);
      dword bits = readDword(bitmapPtr + bword * 4);
      if (bits & bbit) {
         bits &= ~bbit;
         writeDword(bitmapPtr + bword * 4, bits);
         eax = 1;
      }
      else {
         //index was not allocated
         eax = 0;
      }
   }
   else {
      eax = 0;
   }
   if (!eax) {
      //error code is STATUS_INVALID_PARAMETER == 0xc000000d
      setThreadError(0xc000000d);
   }      
   if (doLogLib) {
      msg("call: TlsFree(0x%x) = %d\n", dwTlsIndex, eax);
   }
}

void emu_TlsGetValue(dword /*addr*/) {
   dword dwTlsIndex = pop(SIZE_DWORD);
   if (dwTlsIndex < 64) {
      eax = readDword(fsBase + TEB_TLS_ARRAY + dwTlsIndex * 4);
      setThreadError(0);
   }
   else if (dwTlsIndex < (1024 + 64)) {
      dword exp = readDword(fsBase + TEB_TLS_EXPANSION);
      dwTlsIndex -= 64;
      if (exp == 0) {
         eax = 0;
      }
      else {
         eax = readDword(exp + dwTlsIndex * 4);
      }
      setThreadError(0);
   }
   else {
      eax = 0;
      setThreadError(0xc000000d);
      //error code is STATUS_INVALID_PARAMETER == 0xc000000d
   }
   if (doLogLib) {
      msg("call: TlsGetValue(0x%x) = 0x%x\n", dwTlsIndex, eax);
   }
}

void emu_TlsSetValue(dword /*addr*/) {
   dword dwTlsIndex = pop(SIZE_DWORD);
   dword lpTlsValue = pop(SIZE_DWORD);
   //returns BOOL 0 - fail, 1 - success
   //return is BOOL 0 - fail, 1 - success
   //kernel does no checking on whether index is actually allocated
   if (dwTlsIndex < 64) {
      writeDword(fsBase + TEB_TLS_ARRAY + dwTlsIndex * 4, lpTlsValue);
      eax = 1;
   }
   else if (dwTlsIndex < (1024 + 64)) {
      dword exp = readDword(fsBase + TEB_TLS_EXPANSION);
      dwTlsIndex -= 64;
      if (exp == 0) {
         exp = HeapBase::getHeap()->calloc(0x1000, 1);
         writeDword(fsBase + TEB_TLS_EXPANSION, exp);
      }
      if (exp) {
         writeDword(exp + dwTlsIndex * 4, lpTlsValue);
         eax = 1;
      }
      else {
         //error code is STATUS_NO_MEMORY == 0xc0000017
         //no memory available to allocate expansion page
         eax = 0;
         setThreadError(0xc0000017);
      }
   }
   else {
      eax = 0;
      //error code is STATUS_INVALID_PARAMETER == 0xc000000d
      setThreadError(0xc000000d);
   }
   if (doLogLib) {
      msg("call: TlsSetValue(0x%x, 0x%0x)\n", dwTlsIndex, lpTlsValue);
   }
}

void emu_GetLastError(dword /*addr*/) {
   eax = readDword(fsBase + TEB_LAST_ERROR);
   if (doLogLib) {
      msg("call: GetLastError() = 0x%x\n", eax);
   }
}

void emu_SetLastError(dword /*addr*/) {
   dword err = pop(SIZE_DWORD);
   setThreadError(err);
   if (doLogLib) {
      msg("call: SetLastError(0x%x)\n", err);
   }
}

void emu_AddVectoredExceptionHandler(dword /*addr*/) {
   bool first = pop(SIZE_DWORD) != 0;
   dword handler = pop(SIZE_DWORD);
   addVectoredExceptionHandler(first, handler);
   eax = handler;
   if (doLogLib) {
      msg("call: AddVectoredExceptionHandler(0x%x, 0x%x)= 0x%x\n", first, handler, eax);
   }
}

void emu_RemoveVectoredExceptionHandler(dword /*addr*/) {
   dword handler = pop(SIZE_DWORD);
   removeVectoredExceptionHandler(handler);
   if (doLogLib) {
      msg("call: RemoveVectoredExceptionHandler(0x%x)\n", handler);
   }
}

static void initCriticalSection(dword lpcs, dword spinCount) {
   writeDword(lpcs, 0);   //DebugInfo
   writeDword(lpcs + 4, 0);   //LockCount
   writeDword(lpcs + 8, 0);   //RecursionCount
   writeDword(lpcs + 12, 0);   //OwningThread
   writeDword(lpcs + 16, 0);   //LockSemephore
   writeDword(lpcs + 20, spinCount);   //SpinCount
}

void emu_InitializeCriticalSection(dword /*addr*/) {
   dword lpCriticalSection = pop(SIZE_DWORD);
   initCriticalSection(lpCriticalSection, 0);
   //add lpCriticalSection to list of active critical sections
   if (doLogLib) {
      msg("call: InitializeCriticalSection(0x%x)\n", lpCriticalSection);
   }
}

void emu_InitializeCriticalSectionAndSpinCount(dword /*addr*/) {
   dword lpCriticalSection = pop(SIZE_DWORD);
   dword spinCount = pop(SIZE_DWORD);
   initCriticalSection(lpCriticalSection, spinCount);
   //add lpCriticalSection to list of active critical sections
   
   //prior to vista return os 0 for fail, 1 for success
   //vista+ always returns 1
   eax = 1;
   if (doLogLib) {
      msg("call: InitializeCriticalSectionAndSpinCount(0x%x, 0x%x) = 0x%x\n", lpCriticalSection, spinCount, eax);
   }
}

bool tryEnterCriticalSection(dword /*addr*/) {
   dword lpCriticalSection = pop(SIZE_DWORD);
   //now verify that this is an active critical section
   dword tid = readDword(lpCriticalSection + 12);
   if (tid == 0 || tid == activeThread->handle) {
      dword lockCount = readDword(lpCriticalSection + 4) + 1;
      writeDword(lpCriticalSection + 4, lockCount);
      writeDword(lpCriticalSection + 12, activeThread->handle);
      return true;
   }
   else {
      return false;
   }
}

void emu_EnterCriticalSection(dword addr) {
   if (doLogLib) {
      msg("call: EnterCriticalSection(0x%x)\n", readDword(esp));
   }
   bool success = tryEnterCriticalSection(addr);
   if (success) {
   }
   else {
      //current thread can't enter, it needs to wait
      //need to choose another thread to execute
   }
}

void emu_TryEnterCriticalSection(dword addr) {
   dword arg = readDword(esp);
   eax = tryEnterCriticalSection(addr);
   if (doLogLib) {
      msg("call: TryEnterCriticalSection(0x%x) = %d\n", arg, eax);
   }
}

void emu_LeaveCriticalSection(dword /*addr*/) {
   dword lpCriticalSection = pop(SIZE_DWORD); 
   dword tid = readDword(lpCriticalSection + 12);
   if (tid == activeThread->handle) {
      dword lockCount = readDword(lpCriticalSection + 4) - 1;
      writeDword(lpCriticalSection + 4, lockCount);
      if (lockCount == 0) {
         writeDword(lpCriticalSection + 12, 0);
         //see if any threads are blocking on this critical section
      }
   }
   if (doLogLib) {
      msg("call: LeaveEnterCriticalSection(0x%x)\n", lpCriticalSection);
   }
}

void emu_DeleteCriticalSection(dword /*addr*/) {
   dword lpCriticalSection = pop(SIZE_DWORD); 
   //remove lpCriticalSection from list of active critical sections
   if (doLogLib) {
      msg("call: DeleteCriticalSection(0x%x)\n", lpCriticalSection);
   }
}

void emu_Sleep(dword /*addr*/) {
   dword milliSec = pop(SIZE_DWORD);
   if (doLogLib) {
      msg("call: Sleep(0x%x)\n", milliSec);
   }
}

void emu_InterlockedIncrement(dword /*addr*/) {
   dword addend = pop(SIZE_DWORD); 
   eax = readDword(addend) + 1;
   writeDword(addend, eax);
   if (doLogLib) {
      msg("call: InterlockedIncrement(0x%x) = 0x%x\n", addend, eax);
   }
}

void emu_InterlockedDecrement(dword /*addr*/) {
   dword addend = pop(SIZE_DWORD); 
   eax = readDword(addend) - 1;
   writeDword(addend, eax);
   if (doLogLib) {
      msg("call: InterlockedDecrement(0x%x) = 0x%x\n", addend, eax);
   }
}

void emu_EncodePointer(dword /*addr*/) {
   dword ptr = pop(SIZE_DWORD);
   eax = ptr ^ randVal;
   if (doLogLib) {
      msg("call: EncodePointer(0x%x) = 0x%x\n", ptr, eax);
   }
}

void emu_DecodePointer(dword /*addr*/) {
   dword ptr = pop(SIZE_DWORD);
   eax = ptr ^ randVal;
   if (doLogLib) {
      msg("call: DecodePointer(0x%x) = 0x%x\n", ptr, eax);
   }
}

void emu_lstrlen(unsigned int /*addr*/) {
   dword str = pop(SIZE_DWORD);
   dword arg = str;
   dword len = 0;
   while (isLoaded(str) && get_byte(str)) {
      len++;
      str++;
   }
   eax = len;
   if (doLogLib) {
      msg("call: lstrlen(0x%x) = 0x%x\n", arg, eax);
   }
}

void strcpy_common_wide(dword dest, dword src) {
   dword val;
   while (isLoaded(src)) {
      val = get_word(src);
      src += 2;
      patch_word(dest, val);
      dest += 2;
      if (val == 0) break;
   }
}

void emu_lstrcpyW(unsigned int /*addr*/) {
   eax = pop(SIZE_DWORD);
   dword src = pop(SIZE_DWORD);
   strcpy_common_wide(eax, src);
   if (doLogLib) {
      msg("call: lstrcpyW(0x%x, 0x%x) = 0x%x\n", eax, src, eax);
   }
}

void strcpy_common(dword dest, dword src) {
   dword val;
   while (isLoaded(src)) {
      val = get_byte(src++);
      patch_byte(dest++, val);
      if (val == 0) break;
   }
}

void emu_lstrcpy(unsigned int /*addr*/) {
   eax = pop(SIZE_DWORD);
   dword src = pop(SIZE_DWORD);
   strcpy_common(eax, src);
   if (doLogLib) {
      msg("call: lstrcpy(0x%x, 0x%x) = 0x%x\n", eax, src, eax);
   }
}

void emu_lstrcat(unsigned int /*addr*/) {
   dword dest = pop(SIZE_DWORD);
   eax = dest;
   dword src = pop(SIZE_DWORD);
   //move to end of dest
   while (isLoaded(dest) && get_byte(dest)) dest++;
   strcpy_common(dest, src);
   if (doLogLib) {
      msg("call: lstrcat(0x%x, 0x%x) = 0x%x\n", eax, src, eax);
   }
}

void emu_strcat(unsigned int /*addr*/) {
   dword dest = readDword(esp);
   eax = dest;
   dword src = readDword(esp + 4);
   //move to end of dest
   while (isLoaded(dest) && get_byte(dest)) dest++;
   strcpy_common(dest, src);
   if (doLogLib) {
      msg("call: strcat(0x%x, 0x%x) = 0x%x\n", eax, src, eax);
   }
}

void emu_strcpy(unsigned int /*addr*/) {
   eax = readDword(esp);
   dword src = readDword(esp + 4);
   strcpy_common(eax, src);
   if (doLogLib) {
      msg("call: strcpy(0x%x, 0x%x) = 0x%x\n", eax, src, eax);
   }
}

void strncpy_common(dword dest, dword src, dword n) {
   dword val;
   dword i = 0;
   while (isLoaded(src) && i < n) {
      val = get_byte(src++);
      patch_byte(dest++, val);
      if (val == 0) break;
      i++;
   }
}

void emu_strncpy(unsigned int /*addr*/) {
   eax = readDword(esp);
   dword src = readDword(esp + 4);
   dword n = readDword(esp + 8);
   strncpy_common(eax, src, n);
   if (doLogLib) {
      msg("call: strncpy(0x%x, 0x%x, %d)\n", eax, src, n);
   }
}

void emu_wcsset(unsigned int /*addr*/) {
   dword dest = readDword(esp);
   dword val = readDword(esp + 4);
   eax = dest;
   while (isLoaded(dest) && get_word(dest)) {
      patch_word(dest, val);
      dest += 2;
   }
   if (doLogLib) {
      msg("call: wcsset(0x%x, 0x%x) = 0x%x\n", eax, val, eax);
   }
}

void emu_strlwr(unsigned int /*addr*/) {
   dword dest = readDword(esp);
   eax = dest;
   while (isLoaded(dest)) {
      dword val = get_byte(dest);
      if (val == 0) break;
      patch_byte(dest++, tolower(val));
   }
   if (doLogLib) {
      msg("call: strlwr(0x%x) = 0x%x\n", eax, eax);
   }
}

void emu_RevertToSelf(unsigned int /*addr*/) {
   eax = 1;
   if (doLogLib) {
      msg("call: RevertToSelf() = 1\n");
   }
}

void emu_AreAnyAccessesGranted(unsigned int /*addr*/) {
   eax = 1;
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   if (doLogLib) {
      msg("call: AreAnyAccessesGranted(0x%x, 0x%x) = 1\n", arg1, arg2);
   }
}

void emu_GetBkMode(unsigned int /*addr*/) {
   eax = 0;
   dword arg = pop(SIZE_DWORD);
   if (doLogLib) {
      msg("call: AreAnyAccessesGranted(0x%x) = 0\n", arg);
   }
}

void emu_GdiFlush(unsigned int /*addr*/) {
   eax = 1;
   if (doLogLib) {
      msg("call: GdiFlush() = 1\n");
   }
}

void emu_GetROP2(unsigned int /*addr*/) {
   eax = 0;
   dword arg = pop(SIZE_DWORD);
   if (doLogLib) {
      msg("call: GetROP2(0x%x) = 0\n", arg);
   }
}

void emu_GetBkColor(unsigned int /*addr*/) {
   eax = 0;
   dword arg = pop(SIZE_DWORD);
   if (doLogLib) {
      msg("call: GetBkColor(0x%x) = 0\n", arg);
   }
}

void emu_GdiGetBatchLimit(unsigned int /*addr*/) {
   eax = 20;
   if (doLogLib) {
      msg("call: GdiGetBatchLimit() = %d\n", eax);
   }
}

void emu_StrCmpW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword arg1 = str1;
   dword str2 = pop(SIZE_DWORD);
   dword arg2 = str2;
   eax = 1;
   while (isLoaded(str1) && isLoaded(str2)) {
      dword val1 = get_word(str1);
      dword val2 = get_word(str2);
      int res = val1 - val2;
      if (res) {
         if (res < 0) eax = 0xFFFFFFFF;
         break; 
      }
      else if (val1 == 0) { //end of string
         eax = 0;
         break;
      }
      str1 += 2;
      str2 += 2;      
   }
   if (doLogLib) {
      msg("call: StrCmpW(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_StrSpnA(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword str2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: StrSpnA(0x%x, 0x%x) = %d\n", str1, str2, eax);
   }
}

void emu_StrCmpIW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword arg1 = str1;
   dword str2 = pop(SIZE_DWORD);
   dword arg2 = str2;
   eax = 1;
   while (isLoaded(str1) && isLoaded(str2)) {
      dword val1 = towlower(get_word(str1));
      dword val2 = towlower(get_word(str2));
      int res = val1 - val2;
      if (res) {
         if (res < 0) eax = 0xFFFFFFFF;
         break; 
      }
      else if (val1 == 0) { //end of string
         eax = 0;
         break;
      }
      str1 += 2;
      str2 += 2;      
   }
   if (doLogLib) {
      msg("call: StrCmpIW(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_StrCpyW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword arg1 = str1;
   dword str2 = pop(SIZE_DWORD);
   eax = str1;
   dword arg2 = str2;
   while (isLoaded(str2)) {
      dword val1 = get_word(str2);
      patch_word(str1, val1);
      if (val1 == 0) { //end of string
         break;
      }
      str1 += 2;
      str2 += 2;      
   }
   if (doLogLib) {
      msg("call: StrCpyW(0x%x, 0x%x) = 0x%x\n", arg1, arg2, eax);
   }
}

void emu_StrChrIA(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   int match = tolower(pop(SIZE_DWORD));
   dword val = get_byte(str1);
   eax = 0;
   while (isLoaded(str1) && val) {
      if (tolower(val) == match) {
         eax = str1;
         break;
      }
      val = get_byte(++str1);
   }
   if (doLogLib) {
      msg("call: StrChrIA(0x%x) = 0x%x\n", str1, eax);
   }
}

void emu_StrCSpnIA(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword str2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: emu_StrCSpnIA(0x%x, 0x%x)\n", str1, str2);
   }
}

void emu_StrChrIW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword arg1 = str1;
   int match = towlower(pop(SIZE_DWORD));
   dword val = get_word(str1);
   eax = 0;
   while (isLoaded(str1) && val != 0) {
      if (towlower(val) == match) {
         eax = str1;
         break;
      }
      str1 += 2;
      val = get_word(str1);
   }
   if (doLogLib) {
      msg("call: StrChrIW(0x%x) = 0x%x\n", arg1, eax);
   }
}

void emu_StrCmpNW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword arg1 = str1;
   dword str2 = pop(SIZE_DWORD);
   dword arg2 = str2;
   int n = pop(SIZE_DWORD);
   eax = 0;
   for (int i = 0; i < n && isLoaded(str1) && isLoaded(str2); i++) {
      dword val1 = get_word(str1);
      dword val2 = get_word(str2);
      int res = val1 - val2;
      if (res) {
         eax = res < 0 ? 0xFFFFFFFF : 1;
         break; 
      }
      else if (val1 == 0) { //end of string
         break;
      }
      str1 += 2;
      str2 += 2;      
   }
   if (doLogLib) {
      msg("call: StrCmpNW(0x%x, 0x%x, %d) = %d\n", arg1, arg2, n, eax);
   }
}

void emu_StrCmpNIW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword arg1 = str1;
   dword str2 = pop(SIZE_DWORD);
   dword arg2 = str2;
   int n = pop(SIZE_DWORD);
   eax = 0;
   for (int i = 0; i < n && isLoaded(str1) && isLoaded(str2); i++) {
      dword val1 = towlower(get_word(str1));
      dword val2 = towlower(get_word(str2));
      int res = val1 - val2;
      if (res) {
         eax = (res < 0) ? 0xFFFFFFFF : 1;
         break; 
      }
      else if (val1 == 0) { //end of string
         break;
      }
      str1 += 2;
      str2 += 2;      
   }
   if (doLogLib) {
      msg("call: StrCmpNIW(0x%x, 0x%x, %d) = %d\n", arg1, arg2, n, eax);
   }
}

void emu_StrCSpnIW(unsigned int /*addr*/) {
   dword str1 = pop(SIZE_DWORD);
   dword str2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: StrCmpNIW(0x%x, 0x%x) = %d\n", str1, str2, eax);
   }
}

void emu_GetClientRect(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetClientRect(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_GetACP(unsigned int /*addr*/) {
   eax = 1252;
   if (doLogLib) {
      msg("call: GetACP() = %d\n", eax);
   }
}

void emu_IsCharUpperA(unsigned int /*addr*/) {
   dword ch = pop(SIZE_DWORD);
   eax = isupper(ch);
   if (doLogLib) {
      msg("call: IsCharUpperA(0x%x) = %d\n", ch, eax);
   }
}

void emu_IsCharAlphaA(unsigned int /*addr*/) {
   dword ch = pop(SIZE_DWORD);
   eax = isalpha(ch);
   if (doLogLib) {
      msg("call: IsCharAlphaA(0x%x) = %d\n", ch, eax);
   }
}

void emu_GetIconInfo(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetIconInfo(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_GetWindow(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetWindow(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_IsChild(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: IsChild(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_GetTopWindow(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetTopWindow(0x%x) = %d\n", arg1, eax);
   }
}

void emu_GetWindowContextHelpId(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetWindowContextHelpId(0x%x) = %d\n", arg1, eax);
   }
}

void emu_WindowFromDC(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: WindowFromDC(0x%x) = %d\n", arg1, eax);
   }
}

void emu_GetWindowPlacement(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetWindowPlacement(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_CopyIcon(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: CopyIcon(0x%x) = %d\n", arg1, eax);
   }
}

void emu_IsIconic(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: IsIconic(0x%x) = %d\n", arg1, eax);
   }
}

void emu_GetGUIThreadInfo(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetGUIThreadInfo(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_GetDC(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetDC(0x%x) = %d\n", arg1, eax);
   }
}

void emu_GetTitleBarInfo(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetTitleBarInfo(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_IsWindowUnicode(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: IsWindowUnicode(0x%x) = %d\n", arg1, eax);
   }
}

void emu_IsMenu(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: IsMenu(0x%x) = %d\n", arg1, eax);
   }
}

void emu_GetWindowRect(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetWindowRect(0x%x, 0x%x) = %d\n", arg1, arg2, eax);
   }
}

void emu_IsWindowVisible(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: IsWindowVisible(0x%x) = %d\n", arg1, eax);
   }
}

void emu_GetForegroundWindow(unsigned int /*addr*/) {
   eax = 0x12345678;
   if (doLogLib) {
      msg("call: GetForegroundWindow() = 0x%x\n", eax);
   }
}

void emu_InSendMessage(unsigned int /*addr*/) {
   eax = 0;
   if (doLogLib) {
      msg("call: InSendMessage() = %d\n", eax);
   }
}

void emu_GetWindowTextA(unsigned int /*addr*/) {
   dword arg1 = pop(SIZE_DWORD);
   dword arg2 = pop(SIZE_DWORD);
   dword arg3 = pop(SIZE_DWORD);
   eax = 0;
   if (doLogLib) {
      msg("call: GetWindowTextA(0x%x, 0x%x, 0x%x) = %d\n", arg1, arg2, arg3, eax);
   }
}

void emu_IsUserAnAdmin(unsigned int /*addr*/) {
   eax = 0;
   if (doLogLib) {
      msg("call: IsUserAnAdmin() = %d\n", eax);
   }
}

#define WINDOWS_XP_MAJOR 5
#define WINDOWS_XP_MINOR 1
#ifndef VER_PLATFORM_WIN32_NT
#define VER_PLATFORM_WIN32_NT 2
#endif

void emu_GetVersionExA(unsigned int /*addr*/) {
   dword ptr = pop(SIZE_DWORD);
   dword sz = get_long(ptr);
   eax = 1;
   if (sz != 0x94 && sz != 0x9C) {
      eax = 0;
   }
   else {
      patch_byte(ptr + 4, WINDOWS_XP_MAJOR);
      patch_byte(ptr + 8, WINDOWS_XP_MINOR);
      patch_byte(ptr + 12, 0xa28);
      patch_byte(ptr + 16, VER_PLATFORM_WIN32_NT);
      patch_many_bytes(ptr + 20, "Service Pack 3", 15);
      if (sz == 0x114) { //file in EX related stuff beginning at 0x94
      }
   }
   if (doLogLib) {
      msg("call: GetVersionExA(0x%x) = %d\n", ptr, eax);
   }
}

void emu_GetVersion(unsigned int /*addr*/) {
   eax = 0xa280105;
   if (doLogLib) {
      msg("call: GetVersion() = 0x%x\n", eax);
   }
}

void emu_GetTickCount(unsigned int /*addr*/) {
   eax = (dword)(tsc.ll / 1000000);
   if (doLogLib) {
      msg("call: GetTickCount() = 0x%x\n", eax);
   }
}

void emu_GetSystemTimeAsFileTime(dword /*addr*/) {
   dword lpSystemTimeAsFileTime = pop(SIZE_DWORD);
   quad time = tsc.ll / 100;  //tsc is roughly nanosec counter
   dword tbuf[2];
   quad *t = (quad*)tbuf;
   getSystemBaseTime(tbuf, tbuf + 1);
   t += time;
   writeDword(lpSystemTimeAsFileTime, tbuf[0]);
   writeDword(lpSystemTimeAsFileTime + 4, tbuf[1]);
   if (doLogLib) {
      msg("call: GetSystemTimeAsFileTime(0x%x)\n", lpSystemTimeAsFileTime);
   }
}

void emu_QueryPerformanceCounter(dword /*addr*/) {
   dword lpPerformanceCount = pop(SIZE_DWORD);
   writeDword(lpPerformanceCount, tsc.low);
   writeDword(lpPerformanceCount + 4, tsc.high);
   if (doLogLib) {
      msg("call: QueryPerformanceCounter(0x%x)\n", lpPerformanceCount);
   }
}

void emu_IsDebuggerPresent(dword /*addr*/) {
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   eax = get_byte(peb + 2);
   msg("x86emu: IsDebuggerPresent called\n");
   if (doLogLib) {
      msg("call: IsDebuggerPresent() = %d\n", eax);
   }
}

void emu_CheckRemoteDebuggerPresent(dword /*addr*/) {
   eax = 1;
   dword hProcess = pop(SIZE_DWORD);
   dword pbDebuggerPresent = pop(SIZE_DWORD);
   writeMem(pbDebuggerPresent, 0, SIZE_DWORD);
   msg("x86emu: CheckRemoteDebuggerPresent called\n");
   if (doLogLib) {
      msg("call: CheckRemoteDebuggerPresent(0x%x, 0x%x) = %d\n", hProcess, pbDebuggerPresent, eax);
   }
}

void emu_CloseHandle(dword /*addr*/) {
   dword hObject = pop(SIZE_DWORD);
   msg("x86emu: CloseHandle(0x%x) called\n", hObject);
/*
   if (isValidHandle(hObject)) {
      eax = 1;
      doCloseHandle(hObject);
   }
   else {
      eax = 0;
      //set lastError to 0xC0000008L == STATUS_INVALID_HANDLE
   }
*/   
   eax = 0;    //always fail for now
   if (doLogLib) {
      msg("call: CloseHandle(0x%x) = %d\n", hObject, eax);
   }
}

//from winternl.h
typedef enum _SYSTEM_INFORMATION_CLASS {
   SystemBasicInformation,
   SystemProcessorInformation,
   SystemPerformanceInformation,
   SystemTimeOfDayInformation,
   SystemPathInformation,
   SystemProcessInformation,
   SystemCallCountInformation,
   SystemDeviceInformation,
   SystemProcessorPerformanceInformation,
   SystemFlagsInformation,
   SystemCallTimeInformation,
   SystemModuleInformation,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

#define MAXIMUM_FILENAME_LENGTH 256

typedef struct _SYSTEM_MODULE {
   ULONG Reserved1;
   ULONG Reserved2;
   PVOID ImageBaseAddress;
   ULONG ImageSize;
   ULONG Flags;
   WORD Id;
   WORD Rank;
   WORD w018;
   WORD NameOffset;
   BYTE Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
   ULONG ModulesCount;
   SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

void emu_NtQuerySystemInformation(dword /*addr*/) {
   eax = 0; //success
   dword SystemInformationClass = pop(SIZE_DWORD);
   dword pSystemInformation = pop(SIZE_DWORD);
   dword SystemInformationLength = pop(SIZE_DWORD);
   dword pReturnLength = pop(SIZE_DWORD);
   msg("x86emu: NtQuerySystemInformation(%d, 0x%x, %d, 0x%x) called\n", 
       SystemInformationClass, pSystemInformation, SystemInformationLength, pReturnLength);

   switch (SystemInformationClass) {
      case SystemBasicInformation:
         break;
      case SystemProcessorInformation:
         break;
      case SystemPerformanceInformation:
         break;
      case SystemTimeOfDayInformation:
         break;
      case SystemPathInformation:
         break;
      case SystemProcessInformation:
         break;
      case SystemCallCountInformation:
         break;
      case SystemDeviceInformation:
         break;
      case SystemProcessorPerformanceInformation:
         break;
      case SystemFlagsInformation:
         break;
      case SystemCallTimeInformation:
         break;
      case SystemModuleInformation: {
         HandleNode *hl;
         dword count = 0;
         for (hl = moduleHead; hl; hl = hl->next) {
            count++;
         }
         dword size = count * sizeof(SYSTEM_MODULE) + 4;
         if (SystemInformationLength < size) {
            eax = 0xC0000004;
         }
         else if (pSystemInformation) {
            int i = 0;
            writeMem(pSystemInformation, count, SIZE_DWORD);
            for (hl = moduleHead; hl; hl = hl->next) {
               writeMem(pSystemInformation + 4 + i * sizeof(SYSTEM_MODULE), 
                        0, SIZE_DWORD);
               writeMem(pSystemInformation + 4 + i * sizeof(SYSTEM_MODULE) + 4, 
                        0, SIZE_DWORD);
               writeMem(pSystemInformation + 4 + i * sizeof(SYSTEM_MODULE) + 8, 
                        hl->handle, SIZE_DWORD);
               writeMem(pSystemInformation + 4 + i * sizeof(SYSTEM_MODULE) + 26, 
                        0, SIZE_WORD);
               patch_many_bytes(pSystemInformation + 4 + i * sizeof(SYSTEM_MODULE) + 28, 
                        hl->moduleName, strlen(hl->moduleName) + 1);
            }
         }
         if (pReturnLength) {
            writeMem(pReturnLength, size, SIZE_DWORD);
         }
         break;
      }
      default:
         eax = 0xC0000001; //STATUS_UNSUCCESSFUL
                            //could use STATUS_NOT_IMPLEMENTED 0xC0000002
         break;
   }
//   writeMem(pbDebuggerPresent, 0, SIZE_DWORD);
   if (doLogLib) {
      msg("call: NtQuerySystemInformation(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", 
           SystemInformationClass, pSystemInformation, SystemInformationLength, 
           pReturnLength, eax);
   }
}

typedef enum _THREADINFOCLASS {
   ThreadBasicInformation,
   ThreadTimes,
   ThreadPriority,
   ThreadBasePriority,
   ThreadAffinityMask,
   ThreadImpersonationToken,
   ThreadDescriptorTableEntry,
   ThreadEnableAlignmentFaultFixup,
   ThreadEventPair,
   ThreadQuerySetWin32StartAddress,
   ThreadZeroTlsCell,
   ThreadPerformanceCount,
   ThreadAmILastThread,
   ThreadIdealProcessor,
   ThreadPriorityBoost,
   ThreadSetTlsArrayAddress,
   ThreadIsIoPending,
   ThreadHideFromDebugger
} THREADINFOCLASS, *PTHREADINFOCLASS;

void emu_NtSetInformationThread(dword /*addr*/) {
   eax = 0; //success
   dword ThreadHandle = pop(SIZE_DWORD);
   dword ThreadInformationClass = pop(SIZE_DWORD);
   dword pThreadInformation = pop(SIZE_DWORD);
   dword ThreadInformationLength = pop(SIZE_DWORD);
   msg("x86emu: NtSetInformationThread(0x%08x, %d, 0x%x, %d) called\n", 
       ThreadHandle, ThreadInformationClass, pThreadInformation, ThreadInformationLength);

   switch (ThreadInformationClass) {
      case ThreadHideFromDebugger: {
         break;
      }
   }
   if (doLogLib) {
      msg("call: NtSetInformationThread(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", 
           ThreadHandle, ThreadInformationClass, pThreadInformation, 
           ThreadInformationLength, eax);
   }
}

typedef enum _PROCESSINFOCLASS {
   ProcessBasicInformation = 0,
   ProcessDebugPort = 7
} PROCESSINFOCLASS;

//#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

void emu_NtQueryInformationProcess(dword /*addr*/) {
   eax = 0; //success
   dword ProcessHandle = pop(SIZE_DWORD);
   dword ProcessInformationClass = pop(SIZE_DWORD);
   dword pProcessInformation = pop(SIZE_DWORD);
   dword ProcessInformationLength = pop(SIZE_DWORD);
   dword pReturnLength = pop(SIZE_DWORD);

   msg("x86emu: NtQueryInformationProcess(0x%x, %d, 0x%x, %d, 0x%x) called\n", 
       ProcessHandle, ProcessInformationClass, pProcessInformation, 
       ProcessInformationLength, pReturnLength);

   switch (ProcessInformationClass) {
      case ProcessBasicInformation:
         if (ProcessInformationLength < 24) {
            eax = 0xC0000004;
         }
         else if (pProcessInformation) {
            //get peb base address
            writeMem(pProcessInformation + 4, get_long(fsBase + 0x30), SIZE_DWORD);
            //process id
            writeMem(pProcessInformation + 16, get_long(fsBase + 0x20), SIZE_DWORD);
         }
         if (pReturnLength) {
            writeMem(pReturnLength, 24, SIZE_DWORD);
         }
         break;
      case ProcessDebugPort:
         if (ProcessInformationLength < 4) {
            eax = 0xC0000004;
         }
         else if (pProcessInformation) {
            writeMem(pProcessInformation, 0, SIZE_DWORD);
         }
         if (pReturnLength) {
            writeMem(pReturnLength, 4, SIZE_DWORD);
         }
         break;
      case 30: //RemoveProcessDebugPort ???
         eax = 0xC0000353; //STATUS_PORT_NOT_SET
         break;
      default:
         eax = 0xC0000003;  //STATUS_INVALID_INFO_CLASS
         break;
   }
   if (doLogLib) {
      msg("call: NtQueryInformationProcess(0x%x, %d, 0x%x, %d, 0x%x) = 0x%x\n", 
          ProcessHandle, ProcessInformationClass, pProcessInformation, 
          ProcessInformationLength, pReturnLength, eax);
   }
}

void emu_GetCurrentProcess(dword /*addr*/) {
   eax = 0xffffffff;
   if (doLogLib) {
      msg("call: GetCurrentProcess() = 0x%x\n", eax);
   }
}

void emu_GetCurrentProcessId(dword /*addr*/) {
   eax = get_long(fsBase + TEB_PROCESS_ID);
   if (doLogLib) {
      msg("call: GetCurrentProcessId() = 0x%x\n", eax);
   }
}

void emu_GetCurrentThreadId(dword /*addr*/) {
   eax = get_long(fsBase + TEB_THREAD_ID);
   if (doLogLib) {
      msg("call: GetCurrentThreadId() = 0x%x\n", eax);
   }
}

void emu_GetThreadContext(dword /*addr*/) {
   dword hThread = pop(SIZE_DWORD);
   dword lpContext = pop(SIZE_DWORD);
   WIN_CONTEXT ctx;
   initContext(&ctx);
   ThreadNode *tn = findThread(hThread);
   if (tn && tn != activeThread) {
      regsToContext(&tn->regs, &ctx);
   }
   else {  //take current cpu registers if this is active thread
      //should probably just be an error here
      regsToContext(&cpu, &ctx);
   }
   copyContextToMem(&ctx, lpContext);
   eax = 1;    //non-zero on success,  0 on fail
   if (doLogLib) {
      msg("call: GetThreadContext(0x%x, 0x%x) = %d\n", hThread, lpContext, eax);
   }
}

//need to allocate new TEB here and link to PEB
void emu_CreateThread(dword /*addr*/) {
   dword lpThreadAttributes = pop(SIZE_DWORD);
   dword dwStackSize = pop(SIZE_DWORD);
   dword lpStartAddress = pop(SIZE_DWORD);
   dword lpParameter = pop(SIZE_DWORD);
   dword dwCreationFlags = pop(SIZE_DWORD);
   dword lpThreadId = pop(SIZE_DWORD);
   
   ThreadNode *tn = emu_create_thread(lpStartAddress, lpParameter);
   
   dword newTeb = tn->regs.segBase[FS];
   //read some fields from current thread
   dword peb = readDword(fsBase + TEB_PEB_PTR);
   dword pid = readDword(fsBase + TEB_PROCESS_ID);
   dword lastChance = readDword(fsBase + 0xf84);
   
   dword top = tn->regs.general[ESP] + 32;

   patch_long(newTeb + TEB_PROCESS_ID, pid);
   patch_long(newTeb + TEB_THREAD_ID, tn->id);

   patch_long(newTeb, newTeb + 0xf80);  //last chance SEH record
   patch_long(newTeb + 0xf80, 0xffffffff);  //end of SEH list
   //need kernel32.dll mapped prior to this
   patch_long(newTeb + 0xf84, lastChance);  //kernel32 exception handler

   patch_long(newTeb + TEB_LINEAR_ADDR, newTeb);  //teb self pointer
   patch_long(newTeb + TEB_PEB_PTR, peb);     //peb self pointer   
   
   patch_long(newTeb + TEB_STACK_TOP, top);     //top of stack   
   patch_long(newTeb + TEB_STACK_BOTTOM, top - 0x1000);     //bottom of stack   
   
   if (lpThreadId) {
      writeMem(lpThreadId, tn->id, SIZE_DWORD);
   }
   eax = tn->handle;
   msg("x86emu: CreateThread called: ThreadFunc is 0x%x\n", lpStartAddress);
   if (doLogLib) {
      msg("call: CreateThread(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n", lpThreadAttributes, 
          dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId, eax);
   }
}

//this is a heap allocation routine that also updates a 
//windows PEB
dword addHeapCommon(unsigned int maxSize, unsigned int base) {
   if (fsBase) {
      dword peb = readDword(fsBase + TEB_PEB_PTR);
      dword num_heaps = readDword(peb + PEB_NUM_HEAPS);
      dword max_heaps = readDword(peb + PEB_MAX_HEAPS);
      if (num_heaps < max_heaps) {
         dword res = HeapBase::addHeap(maxSize, base);
         writeDword(peb + PEB_NUM_HEAPS, num_heaps + 1);
         writeDword(peb + SIZEOF_PEB + 4 * num_heaps, res);
         return res;
      }
      else {
         setThreadError(0xc0000017);
         return 0;
      }
   }
   return HeapBase::addHeap(maxSize, base);
}

void emu_HeapCreate(dword /*addr*/) {
   //need to test PEB_NUM_HEAPS against PEB_MAX_HEAPS ??
   
   dword flOptions = pop(SIZE_DWORD); 
   dword dwInitialSize = pop(SIZE_DWORD);
   dword dwMaximumSize = pop(SIZE_DWORD);
   //we are not going to try to do growable heaps here
   if (dwMaximumSize == 0) dwMaximumSize = 0x01000000;
   eax = HeapBase::getHeap()->addHeap(dwMaximumSize);
   //save eax into PEB and update PEB_NUM_HEAPS ??
   if (doLogLib) {
      msg("call: HeapCreate(0x%x, 0x%x, 0x%x) = 0x%x\n", flOptions, 
          dwInitialSize, dwMaximumSize, eax);
   }
}

void emu_HeapDestroy(dword /*addr*/) {
   dword hHeap = pop(SIZE_DWORD); 
   eax = HeapBase::getHeap()->destroyHeap(hHeap);
   if (doLogLib) {
      msg("call: HeapDestroy(0x%x) = 0x%x\n", hHeap, eax); 
   }
}

void emu_GetProcessHeap(dword /*addr*/) {
   eax = HeapBase::getHeap()->getPrimaryHeap();
   if (doLogLib) {
      msg("call: GetProcessHeap() = 0x%x\n", eax); 
   }
}

void emu_HeapAlloc(dword /*addr*/) {
   dword hHeap = pop(SIZE_DWORD); 
   dword dwFlags = pop(SIZE_DWORD);
   dword dwBytes = pop(SIZE_DWORD);
   EmuHeap *h = (EmuHeap*)HeapBase::getHeap()->findHeap(hHeap);
   //are HeapAlloc  blocks zero'ed?
   eax = h ? h->calloc(dwBytes, 1) : 0;
   if (doLogLib) {
      msg("call: HeapAlloc(0x%x, 0x%x, 0x%x) = 0x%x\n", hHeap, dwFlags, dwBytes, eax); 
   }
}

void emu_HeapFree(dword /*addr*/) {
   dword hHeap = pop(SIZE_DWORD); 
   dword dwFlags = pop(SIZE_DWORD);
   dword lpMem = pop(SIZE_DWORD);
   EmuHeap *h = (EmuHeap*)HeapBase::getHeap()->findHeap(hHeap);
   eax = h ? h->free(lpMem) : 0;
   if (doLogLib) {
      msg("call: HeapFree(0x%x, 0x%x, 0x%x) = 0x%x\n", hHeap, dwFlags, lpMem, eax); 
   }
}

void emu_HeapSize(dword /*addr*/) {
   dword hHeap = pop(SIZE_DWORD); 
   dword dwFlags = pop(SIZE_DWORD);
   dword lpMem = pop(SIZE_DWORD);

   EmuHeap *h = (EmuHeap*)HeapBase::getHeap()->findHeap(hHeap);
   eax = h ? h->sizeOf(lpMem) : 0xffffffff;

   if (doLogLib) {
      msg("call: HeapSize(0x%x, 0x%x, 0x%x) = 0x%x\n", hHeap, dwFlags, lpMem, eax); 
   }

}

void emu_GlobalAlloc(dword /*addr*/) {
   dword uFlags = pop(SIZE_DWORD); 
   dword dwSize = pop(SIZE_DWORD);
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   eax = p->calloc(dwSize, 1);
   if (doLogLib) {
      msg("call: GlobalAlloc(0x%x, 0x%x) = 0x%x\n", uFlags, dwSize, eax); 
   }
}

void emu_GlobalFree(dword /*addr*/) {
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   dword ptr = pop(SIZE_DWORD);
   eax = p->free(ptr);
   if (doLogLib) {
      msg("call: GlobalFree(0x%x) = 0x%x\n", ptr, eax); 
   }
}

void emu_GlobalLock(dword /*addr*/) {
   eax = pop(SIZE_DWORD);
   if (doLogLib) {
      msg("call: GlobalLock(0x%x) = 0x%x\n", eax, eax); 
   }
}

void emu_NtAllocateVirtualMemory(dword /*addr*/) {
   dword procHandle = pop(SIZE_DWORD); 
   dword pBaseAddress = pop(SIZE_DWORD); 
   dword zeroBits = pop(SIZE_DWORD); 
   dword pRegionSize = pop(SIZE_DWORD);
   dword flAllocationType = pop(SIZE_DWORD);
   dword flProtect = pop(SIZE_DWORD);
   dword rbase = get_long(pBaseAddress);
   dword dwSize = get_long(pRegionSize);
   dword base = rbase & 0xFFFFF000;
   if (rbase) {
      dword end = (rbase + dwSize + 0xFFF) & 0xFFFFF000;
      dwSize = end - rbase;
   }
   else {
      dwSize = (dwSize + 0xFFF) & 0xFFFFF000;
   }
   dword maddr = MemMgr::mmap(base, dwSize, 0, 0);
   patch_long(pRegionSize, dwSize);
   patch_long(pBaseAddress, maddr);
   eax = 0;   //NTSTATUS
//   msg("x86emu: NtVirtualAllocateMemory called: %d bytes allocated at 0x%x\n", dwSize, addr);
   if (doLogLib) {
      msg("call: NtAllocateVirtualMemory(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
        procHandle, pBaseAddress, zeroBits, pRegionSize, flAllocationType, flProtect, eax); 
   }
}

void emu_VirtualAlloc(dword /*addr*/) {
   dword lpAddress = pop(SIZE_DWORD); 
   dword dwSize = pop(SIZE_DWORD);
   dword flAllocationType = pop(SIZE_DWORD);
   dword flProtect = pop(SIZE_DWORD);
   dword base = lpAddress & 0xFFFFF000;
   if (lpAddress) {
      dword end = (lpAddress + dwSize + 0xFFF) & 0xFFFFF000;
      dwSize = end - lpAddress;
   }
   else {
      dwSize = (dwSize + 0xFFF) & 0xFFFFF000;
   }
   eax = MemMgr::mmap(base, dwSize, 0, 0);
#ifdef DEBUG
   msg("x86emu: VirtualAlloc called: %d bytes allocated at 0x%x\n", dwSize, eax);
#endif
   if (doLogLib) {
      msg("call: VirtualAlloc(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
        lpAddress, dwSize, flAllocationType, flProtect, eax); 
   }
}

void emu_VirtualFree(dword addr) {
   addr = pop(SIZE_DWORD);
   dword dwSize = pop(SIZE_DWORD);
   dword dwFreeType = pop(SIZE_DWORD);
   eax = MemMgr::munmap(addr, dwSize);   
#ifdef DEBUG
   msg("x86emu: VirtualFree(0x%08x, %d) called: 0x%x\n", addr, dwSize, eax);
#endif
   if (doLogLib) {
      msg("call: VirtualFree(0x%x, 0x%x, 0x%x) = 0x%x\n",
          eax, dwSize, dwFreeType, eax); 
   }
}

void emu_VirtualProtect(dword /*addr*/) {
   dword lpAddress = pop(SIZE_DWORD); 
   dword dwSize = pop(SIZE_DWORD);
   dword flNewProtect = pop(SIZE_DWORD);
   dword lpflOldProtect = pop(SIZE_DWORD);
#ifdef DEBUG
   msg("x86emu: VirtualProtect(0x%08x, %d, 0x%x, 0x%08x)\n", 
       lpAddress, dwSize, flNewProtect, lpflOldProtect);
#endif
   eax = 1;
   if (doLogLib) {
      msg("call: VirtualProtect(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x\n",
          lpAddress, dwSize, flNewProtect, lpflOldProtect, eax); 
   }
}

void emu_LocalAlloc(dword /*addr*/) {
   dword uFlags = pop(SIZE_DWORD); 
   dword dwSize = pop(SIZE_DWORD);
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   eax = p->malloc(dwSize);
   if (doLogLib) {
      msg("call: LocalAlloc(0x%x, 0x%x) = 0x%x\n", uFlags, dwSize, eax); 
   }
}

void emu_LocalLock(dword /*addr*/) {
   eax = pop(SIZE_DWORD); //***need to implement a locking mechanism
   if (doLogLib) {
      msg("call: LocalLock(0x%x) = 0x%x\n", eax, eax); 
   }
}

void emu_LocalUnlock(dword /*addr*/) {
   dword hMem = pop(SIZE_DWORD);
   eax = 1;       //***need to implement a locking mechanism
   if (doLogLib) {
      msg("call: LocalUnlock(0x%x) = 0x%x\n", hMem, eax); 
   }
}

void emu_LocalReAlloc(dword /*addr*/) {
   dword hMem = pop(SIZE_DWORD); 
   dword uBytes = pop(SIZE_DWORD);
   dword uFlags = pop(SIZE_DWORD); 
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   eax = p->realloc(hMem, uBytes);
   if (doLogLib) {
      msg("call: LocalReAlloc(0x%x, 0x%x, 0x%x) = 0x%x\n", hMem, uBytes, uFlags, eax); 
   }
}

void emu_LocalFree(dword /*addr*/) {
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   dword ptr = pop(SIZE_DWORD);
   eax = p->free(ptr);
   if (doLogLib) {
      msg("call: LocalFree(0x%x) = 0x%x\n", ptr, eax); 
   }
}

//funcName should be a library function name, and funcAddr its address
hookfunc checkForHook(char *funcName, dword funcAddr, dword moduleId) {
   int i = 0;
   for (i = 0; hookTable[i].fName; i++) {
      if (!strcmp(hookTable[i].fName, funcName)) {
         //if there is an emulation, hook it
         return addHook(funcName, funcAddr, hookTable[i].func, moduleId);
      }
   }
   //there is no emulation, pass all calls to the "unemulated" stub
   return addHook(funcName, funcAddr, unemulated, moduleId);
}

dword myGetProcAddress(dword hModule, dword lpProcName) {
   dword h = 0;
   char *procName = NULL;
   HandleNode *m = findModuleByHandle(hModule);
   if (m == NULL) return 0;
   if (lpProcName < 0x10000) {
      //getting function by ordinal value
      char *dot;
      int len = strlen(m->moduleName) + 16;
      procName = (char*) malloc(len);
      ::qsnprintf(procName, len, "%s_0x%4.4X", m->moduleName, lpProcName);
      dot = strchr(procName, '.');
      if (dot) *dot = '_';
      if ((m->handle & FAKE_HANDLE_BASE) == 0) {
         lpProcName -= m->ordinal_base;
         dword rva = get_long(m->eat + lpProcName * 4);
         if (rva) {
            h = rva + m->handle;
         }
      }
      else {
         //need a fake procaddress when faking module handle
         FakedImport *f = addFakedImport(m, procName);
         h = f->addr;
      }
   }
   else {
      //getting function by name
      procName = getString(lpProcName);
      if ((m->handle & FAKE_HANDLE_BASE) == 0) {
         //binary search through export table to match lpProcName
         int hi = m->NoN - 1;
         int lo = 0;
         while (lo <= hi) {
            int mid = (hi + lo) / 2;
            char *name = getString(get_long(m->ent + mid * 4) + m->handle);
            int res = strcmp(name, procName);
            if (res == 0) {
               free(name);
               lpProcName = get_word(m->eot + mid * 2); // - m->ordinal_base;
               dword rva = get_long(m->eat + lpProcName * 4);
               if (rva) {
                  h = rva + m->handle;
               }
               break;
            }
            else if (res < 0) lo = mid + 1;
            else hi = mid - 1;
            free(name);
         }
      }
      else {
         //need a fake procaddress when faking module handle
         FakedImport *f = addFakedImport(m, procName);
         h = f->addr;
      }         
   }
   free(procName);
   return h;
}

dword myGetProcAddress(dword hModule, const char *procName) {
   dword h = 0;
   HandleNode *m = findModuleByHandle(hModule);
   if (m == NULL) return 0;
   if ((m->handle & FAKE_HANDLE_BASE) == 0) {
      //binary search through export table to match lpProcName
      int hi = m->NoN - 1;
      int lo = 0;
      while (lo <= hi) {
         int mid = (hi + lo) / 2;
         char *name = getString(get_long(m->ent + mid * 4) + m->handle);
         int res = strcmp(name, procName);
         if (res == 0) {
            free(name);
            dword lpProcName = get_word(m->eot + mid * 2); // - m->ordinal_base;
            dword rva = get_long(m->eat + lpProcName * 4);
            if (rva) {
               h = rva + m->handle;
            }
            break;
         }
         else if (res < 0) lo = mid + 1;
         else hi = mid - 1;
         free(name);
      }
   }
   return h;
}

//FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)
void emu_GetProcAddress(dword /*addr*/) {
   static dword address = 0x80000000;
   static dword bad = 0xFFFFFFFF;
   dword hModule = pop(SIZE_DWORD); 
   dword lpProcName = pop(SIZE_DWORD);
   char *procName = NULL;
   int i;
   eax = myGetProcAddress(hModule, lpProcName);
   if (eax) {
      HandleNode *m = findModuleByHandle(hModule);
      procName = reverseLookupExport(eax);
#ifdef DEBUG
      msg("x86emu: GetProcAddress called: %s", procName);
#endif
      //first see if this function is already hooked
      if (procName && findHookByAddr(eax) == NULL) {
         //this is where we need to check if auto hooking is turned on else if (autohook) {
         //if it wasn't hooked, see if there is an emulation for it
         //use h to replace "address" and "bad" below
         for (i = 0; hookTable[i].fName; i++) {
            if (!strcmp(hookTable[i].fName, procName)) {
               //if there is an emulation, hook it
               if (eax == 0) eax = address++;
               addHook(procName, eax, hookTable[i].func, m ? m->id : 0);
               break;
            }
         }
         if (hookTable[i].fName == NULL) {
            //there is no emulation, pass all calls to the "unemulated" stub
            if (eax == 0) eax = bad--;
            addHook(procName, eax, unemulated, m ? m->id : 0);
         }
      }
      else {
      }
   }
   else {
      //lookup failed
   }
#ifdef DEBUG
   msg(" (0x%X)\n", eax);
#endif
   if (doLogLib) {
      if (lpProcName < 0x1000) {
         msg("call: GetProcAddress(0x%x, 0x%4.4x) = 0x%x\n", hModule, lpProcName, eax); 
      }
      else {
         if (procName == NULL) {
            procName = getString(lpProcName);
         }
         msg("call: GetProcAddress(0x%x, \"%s\") = 0x%x\n", hModule, procName, eax); 
      }
   }
   free(procName);
}

/*
 * This is how we build import tables based on calls to 
 * GetProcAddress: create a label at addr from lastProcName.
 */

void makeImportLabel(dword addr, dword val) {
   for (dword cnt = 0; cnt < 4; cnt++) {
      do_unknown(addr + cnt, true); //undefine it
   }
   doDwrd(addr, 4);
   if (val) {
      char *name = reverseLookupExport(val);
      if (name && !set_name(addr, name, SN_NOCHECK | SN_NOWARN)) { //failed, probably duplicate name
         //add numeric suffix until we find an available name
         int nlen = strlen(name) + 32;
         char *newName = (char*)malloc(nlen);
         int idx = 0;
         while (1) {
            ::qsnprintf(newName, nlen, "%s_%d", name, idx++);
            if (set_name(addr, newName, SN_NOCHECK | SN_NOWARN)) {
               break;
            }
         }
         free(newName);
      }
      free(name);
   }
}

HandleNode *moduleCommonA(dword /*addr*/) {
   dword lpModName = pop(SIZE_DWORD);
   char *modName = getString(lpModName);
   modName = checkModuleExtension(modName);
   HandleNode *m = findModuleByName(modName);
   if (m) {
      free(modName);
   }
   else {
      m = addModule(modName, false, 0);
   }
#ifdef DEBUG
   if (m) {
      msg(" called: %s (%X)\n", m->moduleName, m->handle);
   }
#endif
   return m;
}

HandleNode *moduleCommonW(dword /*addr*/) {
   dword lpModName = pop(SIZE_DWORD);
   char *modName = getStringW(lpModName);
   modName = checkModuleExtension(modName);
   HandleNode *m = findModuleByName(modName);
   if (m) {
      free(modName);
   }
   else {
      m = addModule(modName, false, 0);
   }
#ifdef DEBUG
   if (m) {
      msg(" called: %s (%X)\n", m->moduleName, m->handle);
   }
#endif
   return m;
}

HandleNode *moduleCommon(char **modName) {
   *modName = checkModuleExtension(*modName);
   HandleNode *m = findModuleByName(*modName);
   if (m == NULL) {
      m = addModule(*modName, false, 0);
   }
   if (m) {
      msg(" called: %s (%X)\n", m->moduleName, m->handle);
   }
   return m;
}

/*
 * To do: Need to mimic actual GetModuleHandle
 *          add .dll extension if no extension provided
 *          return first occurrence if duplicate suffix
 */

//HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)
void emu_GetModuleHandleA(dword addr) {
#ifdef DEBUG
   msg("x86emu: GetModuleHandle");
#endif
   dword arg = readDword(esp);
   if (arg == 0) {
      dword peb = readDword(fsBase + TEB_PEB_PTR);
      eax = readDword(peb + PEB_IMAGE_BASE);
      pop(SIZE_DWORD);
      if (doLogLib) {
         msg("call: GetModuleHandleA(NULL) = 0x%x\n", eax); 
      }
   }
   else {
      HandleNode *m = moduleCommonA(addr);
      eax = m->handle;
      if (doLogLib) {
         msg("call: GetModuleHandleA(\"%s\") = 0x%x\n", m->moduleName, eax); 
      }
   }
}

//HMODULE __stdcall GetModuleHandleW(LPWSTR lpModuleName)
void emu_GetModuleHandleW(dword addr) {
   msg("x86emu: GetModuleHandle");
   if (readMem(esp, SIZE_DWORD) == 0) {
      dword peb = readDword(fsBase + TEB_PEB_PTR);
      eax = readDword(peb + PEB_IMAGE_BASE);
      pop(SIZE_DWORD);
      if (doLogLib) {
         msg("call: GetModuleHandleW(NULL) = 0x%x\n", eax); 
      }
   }
   else {
      HandleNode *m = moduleCommonW(addr);
      eax = m->handle;
      if (doLogLib) {
         msg("call: GetModuleHandleW(\"%s\") = 0x%x\n", m->moduleName, eax); 
      }
   }
}

void emu_LdrLoadDll(dword /*addr*/) {
   msg("x86emu: LdrLoadDll");
   dword PathToFile = pop(SIZE_DWORD); 
   dword Flags = pop(SIZE_DWORD); 
   dword pModuleFileName = pop(SIZE_DWORD);   //PUNICODE_STRING
   dword pModuleHandle = pop(SIZE_DWORD);

   dword len = get_word(pModuleFileName);
   dword buf = get_long(pModuleFileName + 4);
   char *modName = (char*)malloc(len + 1);
   for (dword i = 0; i < len; i++) {
      modName[i] = (char)get_word(buf + i * 2);
   }
   modName[len] = 0;

   HandleNode *m = moduleCommon(&modName);
   patch_long(pModuleHandle, m->handle);
   eax = 0;
   if (doLogLib) {
      msg("call: LdrLoadDll(0x%x, 0x%x, \"%s\", 0x%x) = 0x%x\n", PathToFile, Flags, modName, pModuleHandle, eax); 
   }
   free(modName);
}

void emu_LdrGetProcedureAddress(dword /*addr*/) {
   static dword address = 0x80000000;
   static dword bad = 0xFFFFFFFF;

   dword hModule = pop(SIZE_DWORD); 
   dword pFunctionName = pop(SIZE_DWORD);   //PANSI_STRING
   dword Ordinal = pop(SIZE_DWORD);  
   dword pFunctionAddress = pop(SIZE_DWORD);

   char *procName = NULL;
   int i;
   dword func;
   if (pFunctionName) {
      func = myGetProcAddress(hModule, get_long(pFunctionName + 4));
   }
   else {
      func = myGetProcAddress(hModule, Ordinal);
   }
   HandleNode *m = findModuleByHandle(hModule);
   procName = reverseLookupExport(func);
#ifdef DEBUG
   msg("x86emu: LdrGetProcedureAddress called: %s", procName);
#endif
   //first see if this function is already hooked
   if (procName && findHookByAddr(func) == NULL) {
      //this is where we need to check if auto hooking is turned on else if (autohook) {
      //if it wasn't hooked, see if there is an emulation for it
      //use h to replace "address" and "bad" below
      for (i = 0; hookTable[i].fName; i++) {
         if (!strcmp(hookTable[i].fName, procName)) {
            //if there is an emulation, hook it
            if (func == 0) func = address++;
            addHook(procName, func, hookTable[i].func, m ? m->id : 0);
            break;
         }
      }
      if (hookTable[i].fName == NULL) {
         //there is no emulation, pass all calls to the "unemulated" stub
         if (func == 0) func = bad--;
         addHook(procName, func, unemulated, m ? m->id : 0);
      }
   }
   else {
   }
#ifdef DEBUG
   msg(" (0x%X)\n", func);
#endif
   eax = func ? 0 : 1;  //need an actual error code here
   if (doLogLib) {
      msg("call: LdrGetProcedureAddress(0x%x, \"%s\", 0x%x, 0x%x) = 0x%x\n", 
          hModule, procName, Ordinal, pFunctionAddress, eax); 
   }
   free(procName);
   patch_long(pFunctionAddress, func);
}

//HMODULE __stdcall emu_FreeLibrary(HANDLE hModule)
void emu_FreeLibrary(dword /*addr*/) {
   dword handle = pop(SIZE_DWORD); 
   eax = 1;
   if (doLogLib) {
      msg("call: FreeLibrary(0x%x) = 0x%x\n", handle, eax); 
   }
}

//HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)
void emu_LoadLibraryA(dword addr) {
#ifdef DEBUG
   msg("x86emu: LoadLibraryA");
#endif
   HandleNode *m = moduleCommonA(addr);
   eax = m->handle;
   if (doLogLib) {
      msg("call: LoadLibraryA(\"%s\") = 0x%x\n", m->moduleName, eax); 
   }
}

//HMODULE __stdcall LoadLibraryW(LPWSTR lpLibFileName)
void emu_LoadLibraryW(dword addr) {
#ifdef DEBUG
   msg("x86emu: LoadLibraryW");
#endif
   HandleNode *m = moduleCommonW(addr);
   eax = m->handle;
   if (doLogLib) {
      msg("call: LoadLibraryW(\"%s\") = 0x%x\n", m->moduleName, eax); 
   }
}

//HMODULE __stdcall LoadLibraryExA(LPCSTR lpLibFileName)
//*** need to honor dwFlags
void emu_LoadLibraryExA(dword addr) {
#ifdef DEBUG
   msg("x86emu: LoadLibraryExA");
#endif
   HandleNode *m = moduleCommonA(addr);
   dword handle = pop(SIZE_DWORD); 
   dword dwFlags = pop(SIZE_DWORD); 
   eax = m->handle;
   if (doLogLib) {
      msg("call: LoadLibraryExA(\"%s\", 0x%x, 0x%x) = 0x%x\n", m->moduleName, handle, dwFlags, eax); 
   }
}

//HMODULE __stdcall LoadLibraryExW(LPWSTR lpLibFileName)
void emu_LoadLibraryExW(dword addr) {
#ifdef DEBUG
   msg("x86emu: LoadLibraryExW");
#endif
   HandleNode *m = moduleCommonW(addr);
   dword handle = pop(SIZE_DWORD); 
   dword dwFlags = pop(SIZE_DWORD); 
   eax = m->handle;
   if (doLogLib) {
      msg("call: LoadLibraryExW(\"%s\", 0x%x, 0x%x) = 0x%x\n", m->moduleName, handle, dwFlags, eax); 
   }
}

void emu_malloc(dword /*addr*/) {
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   dword sz = readDword(esp);
   eax = p->malloc(sz);
   if (doLogLib) {
      msg("call: malloc(0x%x) = 0x%x\n", sz, eax); 
   }
}

void emu_calloc(dword /*addr*/) {
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   dword sz = readDword(esp);
   dword nitems = readDword(esp + 4);
   eax = p->calloc(sz, nitems);
   if (doLogLib) {
      msg("call: calloc(0x%x, 0x%x) = 0x%x\n", sz, nitems, eax); 
   }
}

void emu_realloc(dword /*addr*/) {
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   dword ptr = readDword(esp);
   dword sz = readDword(esp + 4);
   eax = p->realloc(ptr, sz);
   if (doLogLib) {
      msg("call: realloc(0x%x, 0x%x) = 0x%x\n", ptr, sz, eax); 
   }
}

void emu_free(dword /*addr*/) {
   EmuHeap *p = (EmuHeap*)HeapBase::getHeap();
   dword ptr = readDword(esp);
   p->free(ptr);
   if (doLogLib) {
      msg("call: free(0x%x) = 0x%x\n", ptr, eax); 
   }
}

void doImports(PETables &pe) {
   for (thunk_rec *tr = pe.imports; tr; tr = tr->next) {
      HandleNode *m = addModule(tr->dll_name, false, 0);

      dword slot = tr->iat_base + pe.base;
//      msg("processing %s imports slot = %x\n", tr->dll_name, slot);
      for (int i = 0; tr->iat[i]; i++, slot += 4) {
         dword fname = pe.base + tr->iat[i] + 2;
         dword f = 0;
         if (m->handle & FAKE_HANDLE_BASE) {
            f = slot;
         }
         else {  //need to deal with ordinals here
            f = myGetProcAddress(m->handle, fname);
//            reverseLookupExport((dword)f);
         }
//         msg("found %x for %s slot %x\n", f, fname, slot);
         do_unknown(slot, 0);
         doDwrd(slot, 4);
         put_long(slot, f);
         makeImportLabel(slot, f);
         if (f) {
            char *funcname = getString(fname);
            checkForHook(funcname, f, m->id);
            free(funcname);
         }
      }      
   }   
}

//okay to call for ELF, but module list should be empty
HandleNode *moduleFromAddress(dword addr) {
   HandleNode *hl, *result = NULL;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (addr < hl->maxAddr && addr >= hl->handle) {
         result = hl;
         break;
      }
   }
   return result;
}

bool isModuleAddress(dword addr) {
   return moduleFromAddress(addr) != NULL;
}

int reverseLookupFunc(dword EAT, dword func, dword max, dword base) {
   for (dword i = 0; i < max; i++) {
      if ((get_long(EAT + i * 4) + base) == func) return (int)i;
   }
   return -1;
}

int reverseLookupOrd(dword EOT, word ord, dword max) {
   for (dword i = 0; i < max; i++) {
      if (get_word(EOT + i * 2) == ord) return (int)i;
   }
   return -1;
}

//need to add fake_list check for lookups that have been faked
char *reverseLookupExport(dword addr) {
   HandleNode *hl;
   char *fname = NULL;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (addr < hl->maxAddr && addr >= hl->handle) break;
   }
   if (hl) {
      if (hl->handle & FAKE_HANDLE_BASE) {
         FakedImport *f = findFakedImportByAddr(hl, addr);
         if (f) {
            fname = _strdup(f->name);
         }
      }
      else {
         int idx = reverseLookupFunc(hl->eat, addr, hl->NoF, hl->handle);
         if (idx != -1) {
            int ord = reverseLookupOrd(hl->eot, idx, hl->NoN);
            if (ord != -1) {
               fname = getString(get_long(hl->ent + ord * 4) + hl->handle);
   //            msg("x86emu: reverseLookupExport: %X == %s\n", addr, fname);
            }
            else {
               int len = strlen(hl->moduleName) + 16;
               fname = (char*) malloc(len);
               ::qsnprintf(fname, len, "%s_0x%4.4X", hl->moduleName, idx + hl->ordinal_base);
               char *dot = strchr(fname, '.');
               if (dot) *dot = '_';
            }
         }
      }
   }
   else {
      msg("reverseLookupExport failed to locate module containing address 0x%x\n", addr);
   }
   return fname;
}

FunctionInfo *newFunctionInfo(const char *name) {
   FunctionInfo *f = new FunctionInfo;
   f->fname = ::qstrdup(name);
   f->result = 0;
   f->stackItems = 0;
   f->callingConvention = 0;
#if IDA_SDK_VERSION < 650
   f->type = NULL;
   f->fields = NULL;
#endif
   f->next = functionInfoList;
   functionInfoList = f;
   return f;
}   

void clearFunctionInfoList(void) {
   FunctionInfo *f;
   while (functionInfoList) {
      f = functionInfoList;
      functionInfoList = functionInfoList->next;
      ::qfree(f->fname);
      delete f;
   }
   functionInfoList = NULL;
}

#if IDA_SDK_VERSION >= 650

void getIdaTypeInfo(FunctionInfo *f) {
   cm_t cc;
   const type_t *type;
   const p_list *fields;
   f->stackItems = 8;
   if (get_named_type(ti, f->fname, NTF_SYMU, &type, &fields) > 0) {
      f->ftype.deserialize(ti, &type, &fields);
//      f->ftype.get_named_type(ti, f->fname);
      if (f->ftype.is_func()) {
         f->stackItems = f->ftype.get_nargs();
         cc = f->ftype.get_cc();
         if (f->stackItems == 0xffffffffu) {
            //just in case there was an error
            f->stackItems = 8;
         }
         if (cc == CM_CC_STDCALL || cc == CM_CC_FASTCALL) {
            f->callingConvention = CALL_STDCALL;
         }
         else {  //if (cc == CM_CC_CDECL || cc == CM_CC_VOIDARG) {
            f->callingConvention = CALL_CDECL;
         }
      }
   }
}

char *getFunctionPrototype(FunctionInfo *f) {
   char *result = NULL;
   char buf[512];
   buf[0] = 0;
   if (f && f->ftype.is_func()) {
      //parse tinf to create prototype
      result = _strdup(buf);
      int len = strlen(result) + 3 + strlen(f->fname);
      result = (char*)realloc(result, len);
      qstrncat(result, " ", len);
      qstrncat(result, f->fname, len);
      qstrncat(result, "(", len);

      for (unsigned int i = 0; i < f->stackItems; i++) {
         //change to incorporate what we know from Ida
         qstring type_str;
         tinfo_t arginf = f->ftype.get_nth_arg(i);
         arginf.print(&type_str);
         ::qstrncpy(buf, type_str.c_str(), sizeof(buf));
         len = strlen(result) + 3 + strlen(buf);
         result = (char*)realloc(result, len);
         if (i) {
            qstrncat(result, ",", len);
         }
         qstrncat(result, buf, len);
      }
      len = strlen(result) + 2;
      result = (char*)realloc(result, len);
      qstrncat(result, ")", len);
   }
   return result;
}

char *getFunctionReturnType(FunctionInfo *f) {
   if (f && f->ftype.is_func()) {
      tinfo_t retinf = f->ftype.get_rettype();
      if (get_base_type(retinf.get_decltype()) != BT_UNK) {
         qstring type_str;
         retinf.print(&type_str);
         return _strdup(type_str.c_str());
      }
   }
   return NULL;
}

#elif IDA_SDK_VERSION >= 520

void getIdaTypeInfo(FunctionInfo *f) {
   cm_t cc;
   const type_t *type;
   const p_list *fields;
   if (get_named_type(ti, f->fname, NTF_SYMU, &type, &fields) > 0) {
      f->type = type;
      f->fields = fields;
      func_type_info_t info;
      f->stackItems = calc_func_nargs(ti, type);
      cc = get_cc(type[1]);
      if (f->stackItems == 0xffffffffu) {
         //just in case there was an error
         f->stackItems = 0;
      }
      if (cc == CM_CC_STDCALL || cc == CM_CC_FASTCALL) {
         f->callingConvention = CALL_STDCALL;
      }
      else {  //if (cc == CM_CC_CDECL || cc == CM_CC_VOIDARG) {
         f->callingConvention = CALL_CDECL;
      }
   }
}

char *getFunctionPrototype(FunctionInfo *f) {
   char *result = NULL;
   char buf[512];
   buf[0] = 0;
   if (f && f->type) {
      func_type_info_t info;
      int ret = build_funcarg_info(ti, f->type, f->fields,
                         &info, BFI_NOCONST);
      if (ret >= 0) {
         print_type_to_one_line(buf, sizeof(buf), ti, info.rettype.c_str());
      }
      result = _strdup(buf);
      int len = strlen(result) + 3 + strlen(f->fname);
      result = (char*)realloc(result, len);
      qstrncat(result, " ", len);
      qstrncat(result, f->fname, len);
      qstrncat(result, "(", len);

      for (unsigned int i = 0; i < f->stackItems; i++) {
         //change to incorporate what we know from Ida
         print_type_to_one_line(buf, sizeof(buf), NULL, info[i].type.c_str());
         len = strlen(result) + 3 + strlen(buf);
         result = (char*)realloc(result, len);
         if (i) {
            qstrncat(result, ",", len);
         }
         qstrncat(result, buf, len);
      }
      len = strlen(result) + 2;
      result = (char*)realloc(result, len);
      qstrncat(result, ")", len);
   }
   return result;
}

char *getFunctionReturnType(FunctionInfo *f) {
   char buf[512];
   if (f && f->type) {
      func_type_info_t info;
      int ret = build_funcarg_info(ti, f->type, f->fields,
                         &info, BFI_NOCONST);
      if (ret >= 0) {
         print_type_to_one_line(buf, sizeof(buf), ti, info.rettype.c_str());
         return _strdup(buf);
      }
   }
   return NULL;
}

#else 

void getIdaTypeInfo(FunctionInfo *f) {
   cm_t cc;
   const type_t *type;
   const p_list *fields;
   if (get_named_type(ti, f->fname, NTF_SYMU, &type, &fields) > 0) {
      f->type = type;
      f->fields = fields;
      ulong arglocs[20];
      type_t *types[20];
      char *names[20];
      f->stackItems = build_funcarg_arrays(type,
                            fields,
                            arglocs,        // pointer to array of parameter locations
                            types,        // pointer to array of parameter types
                            names,          // pointer to array of parameter names
                            20,           // size of these arrays
                            true);// remove constness from 
      if (f->stackItems >= 1) {
         free_funcarg_arrays(types, names, f->stackItems);   
      }
      cc = get_cc(type[1]);
      if (f->stackItems == 0xffffffffu) {
         //just in case there was an error
         f->stackItems = 0;
      }
      if (cc == CM_CC_STDCALL || cc == CM_CC_FASTCALL) {
         f->callingConvention = CALL_STDCALL;
      }
      else {  //if (cc == CM_CC_CDECL || cc == CM_CC_VOIDARG) {
         f->callingConvention = CALL_CDECL;
      }
   }
}

char *getFunctionPrototype(FunctionInfo *f) {
   char *result = NULL;
   char buf[512];
   buf[0] = 0;
   if (f && f->type) {
      ulong arglocs[20];
      type_t *types[20];
      char *names[20];
      type_t rettype[512];   
      type_t *ret = extract_func_ret_type(f->type, rettype, sizeof(rettype));
      if (ret) {
         print_type_to_one_line(buf, sizeof(buf), ti, rettype);
      }
      result = _strdup(buf);
      int len = strlen(result) + 3 + strlen(f->fname);
      result = (char*)realloc(result, len);
      qstrncat(result, " ", len);
      qstrncat(result, f->fname, len);
      qstrncat(result, "(", len);

      if (f->stackItems) {
         build_funcarg_arrays(f->type, f->fields, arglocs,
                              types, names, 20, true);
      }
      for (unsigned int i = 0; i < f->stackItems; i++) {
         //change to incorporate what we know from Ida
         print_type_to_one_line(buf, sizeof(buf), NULL, types[i]);
         len = strlen(result) + 3 + strlen(buf);
         result = (char*)realloc(result, len);
         if (i) {
            qstrncat(result, ",", len);
         }
         qstrncat(result, buf, len);
      }
      len = strlen(result) + 2;
      result = (char*)realloc(result, len);
      qstrncat(result, ")", len);
      if (f->stackItems) {
         free_funcarg_arrays(types, names, f->stackItems);   
      }
   }
   return result;
}

char *getFunctionReturnType(FunctionInfo *f) {
   char buf[512];
   if (f && f->type) {
      type_t rettype[512];   
      type_t *ret = extract_func_ret_type(f->type, rettype, sizeof(rettype));
      if (ret) {
         print_type_to_one_line(buf, sizeof(buf), ti, rettype);
         return _strdup(buf);
      }
   }
   return NULL;
}

#endif

FunctionInfo *getFunctionInfo(const char *name) {
   FunctionInfo *f;
   for (f = functionInfoList; f; f = f->next) {
      if (!strcmp(name, f->fname)) break;
   }
   if (f == NULL) {
      const type_t *type;
      const p_list *fields;
      if (get_named_type(ti, name, NTF_SYMU, &type, &fields) > 0) {
         f = newFunctionInfo(name);
         getIdaTypeInfo(f);
      }
   }
   return f;
}

void addFunctionInfo(const char *name, dword result, dword nitems, dword callType) {
   FunctionInfo *f;
   for (f = functionInfoList; f; f = f->next) {
      if (!strcmp(name, f->fname)) break;
   }
   if (f == NULL) {
      f = newFunctionInfo(name);
   }
   f->result = result;
   f->stackItems = nitems;
   f->callingConvention = callType;
}

void saveFunctionInfo(Buffer &b) {
   int count = 0;
   FunctionInfo *f;
   for (f = functionInfoList; f; f = f->next) count++;
   b.write(&count, sizeof(count));
   for (f = functionInfoList; f; f = f->next) {
      count = strlen(f->fname) + 1;  //account for null
      b.write(&count, sizeof(count));
      b.write(f->fname, count);  //note this writes the null
      b.write(&f->result, sizeof(f->result));
      b.write(&f->stackItems, sizeof(f->stackItems));
      b.write(&f->callingConvention, sizeof(f->callingConvention));
   }
}

void loadFunctionInfo(Buffer &b) {
   int count = 0, len;
   FunctionInfo *f;
   clearFunctionInfoList();
   b.read(&count, sizeof(count));
   for (; count; count--) {
      f = new FunctionInfo;
//      f = (FunctionInfo*)calloc(1, sizeof(FunctionInfo));
      b.read(&len, sizeof(len));
      f->fname = (char*)::qalloc(len);
      b.read(f->fname, len);
      b.read(&f->result, sizeof(f->result));
      b.read(&f->stackItems, sizeof(f->stackItems));
      b.read(&f->callingConvention, sizeof(f->callingConvention));
#if IDA_SDK_VERSION < 650
      f->type = NULL;
      f->fields = NULL;
#endif   
      f->next = functionInfoList;
      getIdaTypeInfo(f);
      functionInfoList = f;
   }
}

void init_til(const char *tilFile) {
   char err[256];
   *err = 0;
#if IDA_SDK_VERSION < 470
   char *tilpath = get_tilpath();     
#else
   char tilpath[260];
   get_tilpath(tilpath, sizeof(tilpath));     
#endif
   ti = load_til(tilpath, tilFile, err, sizeof(err));
}

void emu_exit(dword retval) {
   msg("Program exited with code %d\n", retval);
   shouldBreak = 1;
}

dword emu_read(dword /*fd*/, dword /*buf*/, dword len) {
   return len;
}

dword emu_write(dword /*fd*/, dword /*buf*/, dword len) {
   return len;
}

dword emu_open(dword /*fname*/, dword /*flags*/, dword /*mode*/) {
   return 0;
}

dword emu_close(dword /*fd*/) {
   return 0;
}

dword linux_mmap(dword addr, dword len, dword prot, dword flags, dword /*fd*/, dword /*offset*/) {
   dword base = addr & 0xFFFFF000;
   if (base) {
      dword end = (base + len + 0xFFF) & 0xFFFFF000;
      len = end - base;
   }
   else {
      len = (len + 0xFFF) & 0xFFFFF000;
   }
   dword res = MemMgr::mmap(base, len, prot, flags);
   if (flags & LINUX_MAP_ANONYMOUS) {
      //mmap'ing a file
   }
   return res;
}

dword linux_munmap() {
   dword len = ecx;
   dword base = ebx & 0xFFFFF000;
   dword end = (base + ecx + 0xFFF) & 0xFFFFF000;
   len = end - base;
   return MemMgr::munmap(base, len);   
}

void emu_exit_group(dword retval) {
   msg("Program exited with code %d\n", retval);
   shouldBreak = 1;
}

void syscall() {
   int syscallNum = eax;
   switch (os_personality) {
      case PERS_LINUX_26:
         switch (syscallNum) {
            case LINUX_SYS_EXIT:
               emu_exit(ebx);
               break;
            case LINUX_SYS_FORK:
               break;
            case LINUX_SYS_READ:
               eax = emu_read(ebx, ecx, edx);
               break;
            case LINUX_SYS_WRITE:
               eax = emu_write(ebx, ecx, edx);
               break;
            case LINUX_SYS_OPEN:
               eax = emu_open(ebx, ecx, edx);
               break;
            case LINUX_SYS_CLOSE:
               eax = emu_close(ebx);
               break;
            case LINUX_SYS_BRK: { //45
               dword cbrk = (dword)kernel_node.altval(OS_LINUX_BRK);
//               segment_t *s = getseg(cbrk - 1);
#if IDA_SDK_VERSION > 520
               segment_t *s = get_prev_seg(ebx);
#else
               segment_t *s = (segment_t *)segs.getn_area(segs.get_prev_area(ebx));
#endif
               if (ebx && ebx != cbrk) {
                  if (ebx > inf.omaxEA) {
                     dword newbrk = (ebx + 0xfff) & ~0xfff;
                     if (s) {
                        cbrk = (dword)s->endEA;
//                        set_segm_end(cbrk - 1, newbrk, SEGMOD_KEEP | SEGMOD_SILENT);
                        set_segm_end(s->startEA, newbrk, SEGMOD_KEEP | SEGMOD_SILENT);
                        if (newbrk > cbrk) {
                           for (dword i = cbrk; i < newbrk; i++) {
                              patch_byte(i, 0);
                           }
                        }
                     }
                     cbrk = newbrk;
                     kernel_node.altset(OS_LINUX_BRK, cbrk);
                  }
               }
               eax = cbrk;
               break;
            }
            case LINUX_SYS_MMAP: //90
               //ebx - addr, ecx - len
               //edx - prot, esi - flags, edi - fd, ebp - offset
               eax = linux_mmap(readDword(ebx), readDword(ebx + 4), readDword(ebx + 8),
                                readDword(ebx + 12), readDword(ebx + 16), readDword(ebx + 20));
               break;
            case LINUX_SYS_MUNMAP: //91
               eax = linux_munmap();
               break;
            case LINUX_SYS_MPROTECT:  // 125
               eax = 0;
               break;
            case LINUX_SYS_MMAP2:  //192
               //ebx - addr, ecx - len
               //edx - prot, esi - flags, edi - fd, ebp - offset >> 12
               eax = linux_mmap(ebx, ecx, edx, esi, edi, ebp << 12);
               break;
            case LINUX_SYS_SET_THREAD_AREA: { //243
               dword desc = readDword(ebx);
               //need a gdt implementation
               if (desc == 0xffffffff) {
                  //we choose desc
                  //should scan thread for one of 3 available descriptors
                  //linux does #define GDT_ENTRY_TLS_MIN 6
                  desc = GDT_ENTRY_TLS_MIN;
                  //we always choose 6 for now
               }
               else if (desc < GDT_ENTRY_TLS_MIN || desc > GDT_ENTRY_TLS_MAX) {
                  eax = (unsigned int)-LINUX_EINVAL;
                  break;
               }
               unsigned int base = readDword(ebx + 4);
               unsigned int limit = readDword(ebx + 8);
               setGdtDesc(desc, base, limit);
               writeDword(ebx, desc);
               eax = 0;
               break;
            }
            case LINUX_SYS_GET_THREAD_AREA: { //243
               unsigned int desc = readDword(ebx);
               //need a gdt/ldt implementation
               if (desc < GDT_ENTRY_TLS_MIN || desc > GDT_ENTRY_TLS_MAX) {
                  eax = (unsigned int)-LINUX_EINVAL;
                  break;
               }
               unsigned int base = getGdtDescBase(desc);
               writeDword(ebx + 4, base);
               unsigned int limit = getGdtDescLimit(desc);
               writeDword(ebx + 8, limit);
               
               //need to handle descriptor flags
               
               eax = 0;
               break;
            }
            case LINUX_SYS_EXIT_GROUP: // 252
               emu_exit_group(ebx);
               break;
         }
         break;
      case PERS_FREEBSD_80:
         switch (syscallNum) {
            case BSD_SYS_EXIT:
               emu_exit(get_long(esp + 4));
               break;
            case BSD_SYS_FORK:
               break;
            case BSD_SYS_READ:
               eax = emu_read(get_long(esp + 4), get_long(esp + 8), get_long(esp + 12));
               break;
            case BSD_SYS_WRITE:
               eax = emu_write(get_long(esp + 4), get_long(esp + 8), get_long(esp + 12));
               break;
            case BSD_SYS_OPEN:
               eax = emu_open(get_long(esp + 4), get_long(esp + 8), get_long(esp + 12));
               break;
            case BSD_SYS_CLOSE:
               eax = emu_close(get_long(esp + 4));
               break;
         }
         break;
   }
}

void linuxSyenter() {
   //syscalls via sysenter use the same user setup as syscalls via int 0x80
   //the difference is that linux (via __kernel_vsyscall) pushes ecx, edx, ebp
   //before invoking sysenter.  Once these are popped, int 0x80 handlers
   //can be used to do all the work
   ebp = pop(SIZE_DWORD);
   edx = pop(SIZE_DWORD);
   ecx = pop(SIZE_DWORD);
   cpu.eip = pop(SIZE_DWORD);  //where sysenter should return to
   syscall();
}

void windowsSysenter() {
}

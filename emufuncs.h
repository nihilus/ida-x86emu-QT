/*
   Source for x86 emulator IdaPro plugin
   File: emufuncs.h
   Copyright (c) 2004-2006 Chris Eagle
   
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

#ifndef __EMULATE_FUNCS_H
#define __EMULATE_FUNCS_H

#include <stdio.h>
#include "buffer.h"
#include "peutils.h"
#include "hooklist.h"

#define CALL_CDECL 0
#define CALL_STDCALL 1

struct FunctionInfo {
   char *fname;
   dword result;
   dword stackItems;
   dword callingConvention;
   const type_t *type;
   const p_list *fields;
   FunctionInfo *next;
};

void emu_lstrlen(unsigned int addr = 0);
void emu_lstrcpyW(unsigned int addr = 0);
void emu_lstrcpy(unsigned int addr = 0);
void emu_strcpy(unsigned int addr = 0);
void emu_strncpy(unsigned int addr = 0);
void emu_lstrcat(unsigned int addr = 0);
void emu_strcat(unsigned int addr = 0);
void emu_wcsset(unsigned int addr = 0);
void emu_strlwr(unsigned int addr);

void emu_CreateThread(unsigned int addr = 0);

void emu_HeapCreate(unsigned int addr = 0);
void emu_HeapDestroy(unsigned int addr = 0);
void emu_HeapAlloc(unsigned int addr = 0);
void emu_HeapFree(unsigned int addr = 0);
void emu_GetProcessHeap(unsigned int addr = 0);

void emu_GlobalAlloc(unsigned int addr = 0);
void emu_GlobalFree(unsigned int addr = 0);
void emu_GlobalLock(unsigned int addr = 0);

void emu_NtAllocateVirtualMemory(unsigned int addr = 0);
void emu_LdrLoadDll(unsigned int addr = 0);
void emu_LdrGetProcedureAddress(unsigned int addr = 0);

void emu_VirtualAlloc(unsigned int addr = 0);
void emu_VirtualFree(unsigned int addr = 0);
void emu_VirtualProtect(unsigned int addr = 0);
void emu_LocalAlloc(unsigned int addr = 0);
void emu_LocalFree(unsigned int addr = 0);
void emu_GetProcAddress(unsigned int addr = 0);
void emu_GetModuleHandleA(unsigned int addr = 0);
void emu_GetModuleHandleW(unsigned int addr = 0);
void emu_LoadLibraryA(unsigned int addr = 0);
void emu_LoadLibraryW(unsigned int addr = 0);

void emu_malloc(unsigned int addr = 0);
void emu_calloc(unsigned int addr = 0);
void emu_realloc(unsigned int addr = 0);
void emu_free(unsigned int addr = 0);

void emu_IsDebuggerPresent(dword addr = 0);
void emu_CheckRemoteDebuggerPresent(dword addr = 0);

void emu_CloseHandle(dword addr = 0);
void emu_NtQuerySystemInformation(dword addr = 0);
void emu_NtQueryInformationProcess(dword addr = 0);
void emu_NtSetInformationThread(dword addr = 0);
void emu_GetCurrentProcessId(dword addr = 0);
void emu_GetCurrentProcess(dword addr = 0);
void emu_GetCurrentThreadId(dword addr = 0);
void emu_GetThreadContext(dword addr = 0);

void emu_RevertToSelf(unsigned int addr);
void emu_AreAnyAccessesGranted(unsigned int addr);
void emu_GetBkMode(unsigned int addr);
void emu_GdiFlush(unsigned int addr);
void emu_GetROP2(unsigned int addr);
void emu_GetBkColor(unsigned int addr);
void emu_GdiGetBatchLimit(unsigned int addr);

void emu_StrChrIW(unsigned int addr);
void emu_StrChrIA(unsigned int addr);
void emu_StrCmpIW(unsigned int addr);
void emu_StrCmpNIW(unsigned int addr);
void emu_StrCmpW(unsigned int addr);
void emu_StrCmpNW(unsigned int addr);
void emu_StrCpyW(unsigned int addr);
void emu_StrSpnA(unsigned int addr);
void emu_StrCSpnIA(unsigned int addr);
void emu_StrCSpnIW(unsigned int addr);

void emu_GetACP(unsigned int addr);
void emu_GetClientRect(unsigned int addr);
void emu_IsCharUpperA(unsigned int addr);
void emu_IsCharAlphaA(unsigned int addr);
void emu_GetIconInfo(unsigned int addr);
void emu_GetWindow(unsigned int addr);
void emu_IsChild(unsigned int addr);
void emu_GetTopWindow(unsigned int addr);
void emu_GetWindowContextHelpId(unsigned int addr);
void emu_WindowFromDC(unsigned int addr);
void emu_GetWindowPlacement(unsigned int addr);
void emu_CopyIcon(unsigned int addr);
void emu_IsIconic(unsigned int addr);
void emu_GetGUIThreadInfo(unsigned int addr);
void emu_GetDC(unsigned int addr);
void emu_GetTitleBarInfo(unsigned int addr);
void emu_IsWindowUnicode(unsigned int addr);
void emu_IsMenu(unsigned int addr);
void emu_GetWindowRect(unsigned int addr);
void emu_IsWindowVisible(unsigned int addr);
void emu_GetForegroundWindow(unsigned int addr);
void emu_InSendMessage(unsigned int addr);
void emu_GetWindowTextA(unsigned int addr);
void emu_IsUserAnAdmin(unsigned int addr);

void emu_GetVersionExA(unsigned int addr);
void emu_GetVersion(unsigned int addr);
void emu_GetTickCount(unsigned int addr);

void emu_GetSystemTimeAsFileTime(dword addr);
void emu_QueryPerformanceCounter(dword addr);

void emu_InterlockedIncrement(dword addr);
void emu_InterlockedDecrement(dword addr);
void emu_EncodePointer(dword addr);
void emu_DecodePointer(dword addr);

void emu_InitializeCriticalSection(dword addr);
void emu_InitializeCriticalSectionAndSpinCount(dword addr);
void emu_TryEnterCriticalSection(dword addr);
void emu_EnterCriticalSection(dword addr);
void emu_LeaveCriticalSection(dword addr);
void emu_DeleteCriticalSection(dword addr);

void emu_AddVectoredExceptionHandler(dword addr);
void emu_RemoveVectoredExceptionHandler(dword addr);

void emu_Sleep(dword addr);

void emu_GetLastError(dword addr);
void emu_SetLastError(dword addr);

void emu_TlsAlloc(dword addr);
void emu_TlsFree(dword addr);
void emu_TlsGetValue(dword addr);
void emu_TlsSetValue(dword addr);

void emu_FlsAlloc(dword addr);
void emu_FlsFree(dword addr);
void emu_FlsGetValue(dword addr);
void emu_FlsSetValue(dword addr);

void emu_GetEnvironmentStringsA(dword addr);
void emu_GetEnvironmentStringsW(dword addr);
void emu_FreeEnvironmentStringsA(dword addr);
void emu_FreeEnvironmentStringsW(dword addr);
void emu_GetCommandLineA(dword addr);
void emu_GetCommandLineW(dword addr);

dword addHeapCommon(unsigned int maxSize, unsigned int base = 0);

enum {
   SYSCALL_FLAVOR_LINUX,
   SYSCALL_FLAVOR_BSD
};

void syscall();

void makeImportLabel(dword addr, dword val);
void saveModuleList(Buffer &b);
void loadModuleList(Buffer &b);
void saveModuleData(Buffer &b);
void loadModuleData(Buffer &b);

struct HandleList;
HandleList *addModule(const char *mod, bool loading, int id);
void addModuleToPeb(dword handle, const char *name, bool loading = false);

hookfunc checkForHook(char *funcName, dword funcAddr, dword moduleId);
void doImports(dword import_drectory, dword size, dword image_base);
void doImports(PETables &pe);
bool isModuleAddress(dword addr);
char *reverseLookupExport(dword addr);

FunctionInfo *getFunctionInfo(const char *name);
void addFunctionInfo(const char *name, dword result, dword nitems, dword callType);
void saveFunctionInfo(Buffer &b);
void loadFunctionInfo(Buffer &b);
char *getFunctionPrototype(FunctionInfo *f);
char *getFunctionReturnType(FunctionInfo *f);

char *getString(dword addr);
void init_til(const char *tilFile);

typedef void (*unemulatedCB)(unsigned int addr, const char *name);

void setUnemulatedCB(unemulatedCB cb);

dword myGetProcAddress(dword hModule, const char *procName);
dword myGetModuleHandle(const char *modName);

typedef enum {NEVER, ASK, ALWAYS} emu_Actions;

extern int emu_alwaysLoadLibrary;
extern int emu_alwaysGetModuleHandle;
extern dword pCmdLineA;

#endif

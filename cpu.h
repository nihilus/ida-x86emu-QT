/*
   Headers for x86 emulator
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

#ifndef __CPU_H
#define __CPU_H

#include "x86defs.h"

#define CPU_VERSION VERSION(1)

typedef struct _DescriptorTableReg_t {
   dword base;
   word limit;
} DescriptorTableReg;

struct Registers {
   dword debug_regs[8];
   dword general[8];
   dword initial_eip;
   dword eip;
   dword eflags;
   dword control[5];
   dword segBase[6];   //cached segment base addresses
   word segReg[6];
   DescriptorTableReg gdtr;
   DescriptorTableReg idtr;
};

extern Registers cpu;

union FpuMmxRegister {
   long double fp;
   unsigned char  b[10];   //only use 8 of these for mmx
   unsigned short s[4];
   unsigned int   i[2];
   unsigned long long ll;
};

struct FloatingPointUnit {
   FpuMmxRegister r[8];
   unsigned short control;
   unsigned short status;
   unsigned short tag;
   unsigned int lastIP;
   unsigned int lastIPseg;
   unsigned int lastDataPointer;
   unsigned int lastDataSeg;
   unsigned short opcode;
};

extern FloatingPointUnit fpu;

struct SSE2Registers {
   unsigned int mxcsr;
   union {
      unsigned char  b[8][16];
      unsigned short w[8][8];
      unsigned int   i[8][4];
      float          f[8][4];
      unsigned long long ll[8][2];
      double         d[8][2];
   } xmm;
};

extern SSE2Registers sse2;

extern ll_union tsc;

//masks to clear out bytes appropriate to the sizes above
extern dword SIZE_MASKS[5];

//masks to clear out bytes appropriate to the sizes above
extern dword SIGN_BITS[5];

//masks to clear out bytes appropriate to the sizes above
extern qword CARRY_BITS[5];

extern byte BITS[5];

extern dword importSavePoint;

extern dword shouldBreak;

typedef struct _IntrRecord_t {
   bool hasError;
   struct _IntrRecord_t *next;
} IntrRecord;

typedef struct _AddrInfo_t {
   dword addr;
   byte type;
   byte modrm;
} AddrInfo;

//struct to describe an instruction being decoded
typedef struct _inst {
   AddrInfo source;
   AddrInfo dest;
   dword opsize;  //operand size for this instruction
   dword prefix;  //any prefix flags
   byte opcode;   //opcode, first or second byte (if first == 0x0F)
} inst;

// Status codes returned by the database blob reading routine
enum {
   X86EMULOAD_OK,                   // state loaded ok
   X86EMULOAD_VERSION_INCOMPATIBLE, // incompatible version
   X86EMULOAD_CORRUPT,              // corrupt/truncated
   X86EMULOAD_UNKNOWN_HOOKFN,       // contains hook to unknown hook function
   X86EMULOAD_NO_NETNODE,           // no save data present
   X86EMUSAVE_OK,                   // state save success
   X86EMUSAVE_FAILED                // state save failed (buffer problems)
};

void initProgram(unsigned int entry);
void enableSEH();

void resetCpu();

void push(dword val, byte size);
dword pop(byte size);
byte readByte(dword addr);
void writeByte(dword addr, byte val);
dword readDword(dword addr);
void writeDword(dword addr, dword val);
void writeMem(dword addr, dword val, byte size);
dword readMem(dword addr, byte size);

int executeInstruction();
void doInterruptReturn();

typedef int (*operand_func)(void);

#ifdef __IDP__

int saveState(netnode &f);
int loadState(netnode &f);

#endif

#endif


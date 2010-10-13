/*
   Headers for x86 emulator
   Copyright (c) 2003, Chris Eagle
   
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

#ifndef __X86DEFS_H
#define __X86DEFS_H

#ifndef __IDP__

#ifndef WIN32

#include <sys/types.h>
typedef int64_t quad;
typedef u_int64_t uquad;

#else   //WIN32

typedef __int64 quad;
typedef unsigned __int64 uquad;

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef int int32_t;

#endif  //WIN32

typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;

// Use printf instead of msg when not using Ida
#define msg printf

#else   //#ifdef __IDP__

#ifndef _MSC_VER
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif  // USE_DANGEROUS_FUNCTIONS
#endif  //_MSC_VER

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>

typedef __int64 quad;
typedef unsigned __int64 uquad;

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef int int32_t;

#include "sdk_versions.h"

#endif

typedef uchar  byte;
typedef ushort word;
typedef uint   dword;
typedef uquad  qword;

#define CARRY 0x1
#define PARITY 0x4
#define AUX_CARRY 0x10
#define ZERO  0x40
#define SIGN 0x80
#define TRAP 0x100
#define INTERRUPT 0x200
#define DIRECTION 0x400
#define OVERFLOW 0x800

#define CF CARRY
#define PF PARITY
#define AF AUX_CARRY
#define ZF ZERO
#define SF SIGN
#define TF TRAP
#define IF INTERRUPT
#define DF DIRECTION
#define OF OVERFLOW

#define RESERVED_FLAGS 0xFFC0802A
#define RING_3_FLAGS (CF | PF | AF | ZF | SF | OF | DF | TF)
#define RING_0_FLAGS (0xFFFFFFFF & ~RESERVED_FLAGS)

#define D (cpu.eflags & DF)

#define SET(x) (cpu.eflags |= (x))
#define CLEAR(x) (cpu.eflags &= (~x))

#define O (cpu.eflags & OF)
#define NO (!(cpu.eflags & OF))

#define B (cpu.eflags & CF)
#define C B
#define NAE B
#define NB (!(cpu.eflags & CF))
#define AE NB
#define NC NB

#define E (cpu.eflags & ZF)
#define Z E
#define NE (!(cpu.eflags & ZF))
#define NZ NE

#define BE (cpu.eflags & (ZF | CF))
#define NA BE
#define NBE (!(cpu.eflags & (ZF | CF)))
#define A NBE

#define S (cpu.eflags & SF)
#define NS (!(cpu.eflags & SF))

#define P (cpu.eflags & PF)
#define PE P
#define NP (!(cpu.eflags & PF))
#define PO NP

#define L (((cpu.eflags & (SF | OF)) == SF) || \
          ((cpu.eflags & (SF | OF)) == OF))
#define NGE L
#define NL (((cpu.eflags & (SF | OF)) == 0) || \
           ((cpu.eflags & (SF | OF)) == (SF | OF)))
#define GE NL

#define LE (((cpu.eflags & (SF | OF)) == SF) || \
           ((cpu.eflags & (SF | OF)) == OF)  || Z)
#define NG LE
#define NLE ((((cpu.eflags & (SF | OF)) == 0) || \
            ((cpu.eflags & (SF | OF)) == (SF | OF))) && NZ)
#define G NLE

#define H_MASK 0x0000FF00

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3
#define ESP 4
#define EBP 5
#define ESI 6
#define EDI 7

#define eax (cpu.general[EAX])
#define ecx (cpu.general[ECX])
#define edx (cpu.general[EDX])
#define ebx (cpu.general[EBX])
#define esp (cpu.general[ESP])
#define ebp (cpu.general[EBP])
#define esi (cpu.general[ESI])
#define edi (cpu.general[EDI])

#define CS 0
#define SS 1
#define DS 2
#define ES 3
#define FS 4
#define GS 5

#define cs (cpu.segReg[CS])
#define ss (cpu.segReg[SS])
#define ds (cpu.segReg[DS])
#define es (cpu.segReg[ES])
#define fs (cpu.segReg[FS])
#define gs (cpu.segReg[GS])

#define csBase (cpu.segBase[CS])
#define ssBase (cpu.segBase[SS])
#define dsBase (cpu.segBase[DS])
#define esBase (cpu.segBase[ES])
#define fsBase (cpu.segBase[FS])    //FS:[0] -> SEH for Win32
#define gsBase (cpu.segBase[GS])

#define CR0 0
#define CR1 1
#define CR2 2
#define CR3 3
#define CR4 4

#define cr0 (cpu.control[CR0])
#define cr1 (cpu.control[CR1])
#define cr2 (cpu.control[CR2])
#define cr3 (cpu.control[CR3])
#define cr4 (cpu.control[CR4])

#define DR0 0
#define DR1 1
#define DR2 2
#define DR3 3
#define DR4 4
#define DR5 5
#define DR6 6
#define DR7 7

#define dr0 (cpu.debug_regs[DR0])
#define dr1 (cpu.debug_regs[DR1])
#define dr2 (cpu.debug_regs[DR2])
#define dr3 (cpu.debug_regs[DR3])
#define dr4 (cpu.debug_regs[DR4])
#define dr5 (cpu.debug_regs[DR5])
#define dr6 (cpu.debug_regs[DR6])
#define dr7 (cpu.debug_regs[DR7])

#define MOD_0 0
#define MOD_1 0x40
#define MOD_2 0x80
#define MOD_3 0xC0

#define RM(x)     ((x) & 0x07)
#define MOD(x)    ((x) & 0xC0)
#define REG(x) (((x) >> 3) & 0x07)
#define HAS_SIB(x) (RM(x) == 4)

#define SCALE(x) (1 << ((x) >> 6))
#define INDEX(x) (((x) >> 3) & 0x07)
#define BASE(x)  ((x) & 0x07)

#define PREFIX_LOCK  0x01
#define PREFIX_REPNE 0x02
#define PREFIX_REP   0x04
#define PREFIX_CS    0x08
#define PREFIX_SS    0x10
#define PREFIX_DS    0x20
#define PREFIX_ES    0x40
#define PREFIX_FS    0x80
#define PREFIX_GS    0x100
#define PREFIX_SIZE    0x200
#define PREFIX_ADDR    0x400
#define PREFIX_SIMD    0x800

#define SEG_MASK     0x1F8

//operand types
#define TYPE_REG  1
#define TYPE_IMM  2
#define TYPE_MEM  4

//operand sizes
#define SIZE_BYTE 1
#define SIZE_WORD 2
#define SIZE_DWORD 4

//FPU Flags
#define FPU_INVALID 0x1
#define FPU_DENORMALIZED 0x2
#define FPU_ZERODIVIDE 0x4
#define FPU_OVERFLOW 0x8
#define FPU_UNDERFLOW 0x10
#define FPU_PRECISION  0x20
#define FPU_STACKFAULT 0x40
#define FPU_ERRORSUMMARY 0x80
#define FPU_CONDITIONS 0x4700
#define FPU_C0 0x100
#define FPU_C1 0x200
#define FPU_C2 0x400
#define FPU_C3 0x4000
#define FPU_TOS 0x3800
#define FPU_BUSY 0x8000

#define FPU_SET(x) (fpu.status |= (x))
#define FPU_GET(x) (fpu.status & (x))
#define FPU_MASK_GET(x) (fpu.control & (x))
#define FPU_CLEAR(x) (fpu.status &= (~x))

#define FPU_TAG0 0x3
#define FPU_TAG1 0xC
#define FPU_TAG2 0x30
#define FPU_TAG3 0xC0
#define FPU_TAG4 0x300
#define FPU_TAG5 0xC00
#define FPU_TAG6 0x3000
#define FPU_TAG7 0xC000

#define FPU_ZERO_TAG 0
#define FPU_VALID_TAG 1
#define FPU_SPECIAL_TAG 2
#define FPU_EMPTY_TAG 3

/*
#define R0 0
#define R1 1
#define R2 2
#define R3 3
#define R4 4
#define R5 5
#define R6 6
#define R7 7

#define r0 (fpu.r[0])
#define r1 (fpu.r[1])
#define r2 (fpu.r[2])
#define r3 (fpu.r[3])
#define r4 (fpu.r[4])
#define r5 (fpu.r[5])
#define r6 (fpu.r[6])
#define r7 (fpu.r[7])

#define r(n) (fpu.r[n])
*/
#define fpuStackTop ((fpu.status >> 11) & 7)

void getSystemBaseTime(dword *timeLow, dword *timeHigh);
void getRandomBytes(void *buf, unsigned int len);

extern bool doTrace;
extern bool doTrack;
extern unsigned int randVal;

#define INTx80_MAGIC 0xBABEF00D

#ifdef __IDP__
//if building an IDA plugin, then here are some defines

//heap personality type values
#define LEGACY_HEAP 100
#define DLMALLOC_2_7_2_HEAP 101
#define JEMALLOC_HEAP 102
#define PHKMALLOC_HEAP 103
#define RTL_HEAP 104

//various emulator related altval indicies
#define X86_EMU_INIT 1
#define HEAP_PERSONALITY 5
#define OS_PERSONALITY 6
#define CPU_PERSONALITY 7
#define X86_MINEA 10
#define X86_MAXEA 11
#define X86_RANDVAL 12
#define SYSTEM_TIME_LOW 13
#define SYSTEM_TIME_HIGH 14
//this would be a kernel32 variable pointing into the heap
#define EMU_COMMAND_LINE 15
#endif

#endif

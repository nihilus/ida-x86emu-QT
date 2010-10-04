#ifndef __WIN_CONTEXT_H
#define __WIN_CONTEXT_H

#define SIZEOF_387_REGS      80
#define MAXIMUM_EXTENSION    512

struct WIN_FLOATING_SAVE_AREA {
   dword   ControlWord;
   dword   StatusWord;
   dword   TagWord;
   dword   ErrorOffset;
   dword   ErrorSelector;
   dword   DataOffset;
   dword   DataSelector;
   byte    RegisterArea[SIZEOF_387_REGS];
   dword   Cr0NpxState;
};

struct WIN_CONTEXT {

   dword ContextFlags;

   dword   Dr0;
   dword   Dr1;
   dword   Dr2;
   dword   Dr3;
   dword   Dr6;
   dword   Dr7;

   WIN_FLOATING_SAVE_AREA FloatSave;

   dword   SegGs;
   dword   SegFs;
   dword   SegEs;
   dword   SegDs;

   dword   Edi;   //0x9C
   dword   Esi;   //0xA0
   dword   Ebx;   //0xA4
   dword   Edx;   //0xA8
   dword   Ecx;   //0xAC
   dword   Eax;   //0xB0

   dword   Ebp;   //0xB4
   dword   Eip;   //0xB8
   dword   SegCs;
   dword   EFlags;
   dword   Esp;
   dword   SegSs;

   byte   ExtendedRegisters[MAXIMUM_EXTENSION];

};

void regsToContext(Registers *regs, WIN_CONTEXT *ctx);
void contextToRegs(WIN_CONTEXT *ctx, Registers *regs);
void initContext(WIN_CONTEXT *ctx);
void copyContextToMem(WIN_CONTEXT *ctx, dword addr);


#endif

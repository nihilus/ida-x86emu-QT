/*
   Source for x86 emulator IdaPro plugin
   File: memmgr.cpp
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

#define NO_OBSOLETE_FUNCS

#include <ida.hpp>
#include <idp.hpp>
#include <srarea.hpp>
#include <segment.hpp>

#include "memmgr.h"
#include "sdk_versions.h"

//lifted from intel.hpp
#define R_fs 33

#if IDA_SDK_VERSION < 500
#define SEGDEL_KEEP 0
#define SEGDEL_SILENT 1
#endif

#if IDA_SDK_VERSION < 530
#define SEGMOD_SILENT 0
#define SEGMOD_KEEP 0
#else
#define SEGDEL_KEEP SEGMOD_KEEP
#define SEGDEL_SILENT SEGMOD_SILENT
#endif


#define SEG_RESERVE 200

static bool haveTEB = false;
static sel_t tebSel = 0;

void createNewSegment(const char *name, dword base, dword size) {
//msg("createNewSegment: %s\n", name);
   //create the new segment
   segment_t s;
   memset(&s, 0, sizeof(s));
   if (strcmp(name, ".teb") == 0) {
      haveTEB = true;
      tebSel = s.sel = allocate_selector(base >> 4);
      SetDefaultRegisterValue(NULL, R_fs, s.sel);
   }
   s.startEA = base;
   s.endEA = base + size;
   s.align = saRelPara;
   s.comb = scPub;
   s.perm = SEGPERM_WRITE | SEGPERM_READ | SEGPERM_EXEC;
   s.bitness = 1;   //== 32
   s.type = SEG_CODE;
   s.color = DEFCOLOR;
   
//   if (add_segm_ex(&s, name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
   if (add_segm_ex(&s, name, "CODE", ADDSEG_QUIET | ADDSEG_NOSREG)) {
      //zero out the newly created segment
      for (ea_t ea = s.startEA; ea < s.endEA; ea++) {
         patch_byte(ea, 0);
      }
      if (haveTEB) {
         SetDefaultRegisterValue(&s, R_fs, tebSel);
      }
   }
}

segment_t *next_seg(ea_t addr) {
#if IDA_SDK_VERSION >= 530
   return get_next_seg(addr);
#else
   int snum = segs.get_next_area(addr);
   if (snum == -1) {
      return NULL;
   }
   else {
      return getnseg(snum);
   }
#endif
}

/*
static const char memmgr_node_name[] = "$ X86emu memory manager";

//The IDA database node identifier into which the plug-in will
//store its state information when the database is saved.
static netnode memmgr_node(x86emu_node_name);

MemMgr::MemMgr() {
   if (netnode_exist(memmgr_node)) {
   }
   else {
      memmgr_node.create(memmgr_node_name);
   }
}
*/

void MemMgr::reserve(dword addr, dword size) {
   segment_t *s = getseg(addr);
   if (s) {
      size = (size + 0xFFF) & 0xFFFFF000;
      dword end = addr + size;
      if (end > s->endEA) {
         segment_t *n = next_seg(addr);
         if (n) {
            if (n->startEA <= end) {
               //no room so fail
               return;
            }
         }
         else {
            if (end < s->startEA) {
               //end wrapped around so fail
               return;
            }
         }
         netnode segnode(s->startEA);
         segnode.altset(SEG_RESERVE, end, 'Z');
      }
   }
}

dword MemMgr::mapFixed(dword addr, dword size, dword /*prot*/, dword flags, const char *name) {
   if (addr == 0 || (flags & MM_MAP_FIXED) == 0) {
      return BADADDR;
   }
   dword end = addr + size;
   segment_t *s = getseg(addr);
   segment_t *n = next_seg(addr);

   while (n && end >= n->endEA) {
      //range completely consumes next segment
      del_segm(n->startEA, SEGDEL_KEEP | SEGDEL_SILENT);
      n = next_seg(addr);
   }
   if (n && end > n->startEA) {
      //range partly overlaps next segment
      set_segm_start(n->startEA, end, SEGMOD_SILENT);
   }

   if (s) {
      if (s->startEA < addr) {
         //may need to split segment
         //addr == s->startEA
         if (end >= s->endEA) {
            //new extends beyond end of s
            set_segm_end(s->startEA, addr, SEGMOD_SILENT);
         }
         else {
            //old completely overlaps new
         }
      }
      else {
         //addr == s->startEA
         if (end >= s->endEA) {
            //new completely overlaps s
            del_segm(s->startEA, SEGDEL_KEEP | SEGDEL_SILENT);
         }
         else {
            //need to move startEA
            set_segm_start(s->startEA, end, SEGMOD_SILENT);
         }
      }
   }
   
   dword suffix = (addr >> 12) & 0xFFFFF;
   if (name == NULL) {
      char segName[64];
      ::qsnprintf(segName, sizeof(segName), "mmap_%05x", suffix);
      createNewSegment(segName, addr, size);
   }
   else {
      createNewSegment(name, addr, size);
   }
   return addr;
}

dword MemMgr::mmap(dword addr, dword size, dword prot, dword flags, const char *name) {
   if (flags & MM_MAP_FIXED) {
      return mapFixed(addr, size, prot, flags, name);
   }
   if (addr == 0) {
      addr = kernel_node.altval(OS_MIN_ADDR);
//      addr = inf.minEA;
   }
   while (1) {
      segment_t *s = getseg(addr);
      if (s == NULL) {            
         segment_t *n = next_seg(addr);
         dword avail = 0;
         if (n) {
            avail = n->startEA - addr;
         }
         else {
            avail = 0 - addr;
         }
         if (avail >= size) {
            dword suffix = (addr >> 12) & 0xFFFFF;
            if (name == NULL) {
               char segName[64];
               ::qsnprintf(segName, sizeof(segName), "mmap_%05x", suffix);
               createNewSegment(segName, addr, size);
            }
            else {
               createNewSegment(name, addr, size);
            }
            return addr;
         }
         if (n == NULL) {
            return BADADDR;
         }
         s = n;
      }
      addr = (s->endEA + 0xFFF) & 0xFFFFF000;
   }
}

dword MemMgr::munmap(dword addr, dword size) {
   segment_t *s = getseg(addr);
   size = (size + 0xFFF) & 0xFFFFF000;
   dword end = addr + size;
   if (s) {
      if (end >= s->endEA) {
         del_segm(addr, SEGDEL_KEEP);
      }
      else {
         set_segm_start(addr, end, SEGMOD_KEEP);
      }
      return 0;
   }
   return 0xFFFFFFFF;
}


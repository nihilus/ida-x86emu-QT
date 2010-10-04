/*
   Source for x86 emulator IdaPro plugin
   File: emuthreads.cpp
   Copyright (c) 2006, Chris Eagle
   
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

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif

#include "x86defs.h"
#include "emuthreads.h"
#include "seh.h"
#include "memmgr.h"

#include <segment.hpp>

#define DEFAULT_STACK_SIZE 0x100000

ThreadNode *threadList = NULL;
ThreadNode *activeThread = NULL;


/*
 * Figure out a new, unused thread id to assign to the new thread
 */
dword getNewThreadHandle() {
   return threadList ? (threadList->handle + 1) : THREAD_HANDLE_BASE;  
}

/*
 * Figure out a new, unused thread id to assign to the new thread
 */
dword getNewThreadId() {
   return threadList ? (threadList->id + 1) : THREAD_ID_BASE;  
}

/*
 * we need to find a memory hole in which to allocate a new stack
 * for a new thread.  This is not a great algorithm, but it should 
 * work well enough for now.  Need to deconflict with heap space.
 * Should really rewrite to allocate space from emulation heap.
 * Should also look for holes created by destroyed threads
 */
dword getNewStackLocation() {
   int count = 1;
   char buf[16];
   segment_t *s = get_segm_by_name(".stack");
   dword top = s->endEA + 0xFFFF;
   while (getseg(top)) {
      top += 0x10000;
      count++;
   }
   qsnprintf(buf, sizeof(buf), ".stack%d", count);
   MemMgr::mmap(top - 0xFFFF, 0x1000, 0, 0, buf);
   return top + 1;
}

/*
 * This constructor should be used for only one thread, the main thread
 * which is declared as a global in cpu.cpp
 */
ThreadNode::ThreadNode() {
   id = getNewThreadId();
   handle = getNewThreadHandle();
   hasStarted = 1;
   threadArg = 0;
   next = NULL;
}

ThreadNode::ThreadNode(dword threadFunc, dword threadArg) {
   next = NULL;
   id = getNewThreadId();
   handle = getNewThreadHandle();
   hasStarted = 0;
   regs = cpu;
   regs.eip = threadFunc;
   this->threadArg = threadArg;
   
   //create thread stack
   dword top;
   regs.general[ESP] = top = getNewStackLocation();
   //the rest should really only be done for Windows binaries
   if (usingSEH()) {
      regs.segBase[FS] = top - 16;
      regs.general[ESP] -= 32;
   }
}

ThreadNode::ThreadNode(Buffer &b, dword currentActive) {
   next = NULL;
   b.read((char*)&handle, sizeof(handle));
   b.read((char*)&id, sizeof(id));
   b.read((char*)&hasStarted, sizeof(hasStarted));
   b.read((char*)&threadArg, sizeof(threadArg));
   b.read((char*)&regs, sizeof(regs));
}
   
void ThreadNode::save(Buffer &b, bool saveStack) {
   b.write((char*)&handle, sizeof(handle));
   b.write((char*)&id, sizeof(id));
   b.write((char*)&hasStarted, sizeof(hasStarted));
   b.write((char*)&threadArg, sizeof(threadArg));
   b.write((char*)&regs, sizeof(regs));
}

/*
 * return thread handle for new thread
 */
ThreadNode *emu_create_thread(dword threadFunc, dword threadArg) {
   ThreadNode *tn = new ThreadNode(threadFunc, threadArg);
   tn->next = threadList;
   threadList = tn;
   return tn;
}

/*
 * destroy the thread indicated by threadId.  Should add code to 
 * prevent destruction of the main thread
 * return the next thread to run (currently always the main thread)
 */
ThreadNode *emu_destroy_thread(dword threadId) {
   ThreadNode *prev = NULL;
   ThreadNode *tn = NULL, *mainThread = NULL;
   for (tn = threadList; tn; tn = tn->next) {
      //doing the following test first prevents the main thread
      //from being destroyed
      if (tn->handle == THREAD_HANDLE_BASE) {
         mainThread = tn;
      }
      else if (tn->handle == threadId) {
         ThreadNode *delThread = tn;
         //free up thread stack
#ifdef SEGDEL_PERM      
         del_segm(tn->regs.general[ESP] - 1, SEGDEL_PERM | SEGDEL_SILENT);      
#else
         del_segm(tn->regs.general[ESP] - 1, 1);      
#endif
         if (prev) {
            prev->next = tn->next;
            tn = prev;
         }
         else {
            tn = threadList = tn->next;
         }
         msg("Destroyed thread 0x%x\n", tn->handle);
/*  //delete threads stack segment
         delete delThread->stack;
*/
         delete delThread;
      }
      prev = tn;
   }
   //cause a break since we are switching threads
   shouldBreak = 1;
   return mainThread;
}

/*
 * switch threads
 */
void emu_switch_threads(ThreadNode *new_thread) {
   if (activeThread != new_thread) {
      if (activeThread) {
         memcpy(&activeThread->regs, &cpu, sizeof(Registers));
      }
      activeThread = new_thread;
      memcpy(&cpu, &new_thread->regs, sizeof(Registers));
   
      if (!new_thread->hasStarted) {
         push(new_thread->threadArg, SIZE_DWORD);
         //push special thread return address
         push(THREAD_MAGIC, SIZE_DWORD);
         new_thread->hasStarted = 1;
      }
   }
}

/*
 * locate the thread with the given handle
 */
ThreadNode *findThread(dword handle) {
   for (ThreadNode *tn = threadList; tn; tn = tn->next) {
      if (tn->handle == handle) return tn;
   }
   return NULL;
}


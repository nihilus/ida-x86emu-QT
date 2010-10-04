/*
   Source for x86 emulator IdaPro plugin
   File: emuheap.h
   Copyright (c) 2004, Chris Eagle
   
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

#ifndef __EMUHEAP_H
#define __EMUHEAP_H

#include "buffer.h"

#define HEAP_ERROR 0xFFFFFFFF
#define HEAP_MAGIC 0xDEADBEEF

class MallocNode {
   friend class EmuHeap;
public:
   MallocNode(unsigned int size, unsigned int base);
   MallocNode(Buffer &b);

   void save(Buffer &b);

   const MallocNode *nextNode() const {return next;};
   int getBase() const {return base;};
   int getSize() const {return size;};

private:
   unsigned int base;
   unsigned char *block;
   unsigned int size;
   MallocNode *next;
};

class EmuHeap {
public:
   EmuHeap();
   EmuHeap(unsigned int baseAddr, unsigned int currSize, unsigned int maxSize, EmuHeap *next = 0);
   EmuHeap(const char *seg, unsigned int sz);
   EmuHeap(Buffer &b);
   ~EmuHeap();
   unsigned int malloc(unsigned int size);
   unsigned int calloc(unsigned int nmemb, unsigned int size);
   unsigned int free(unsigned int addr);
   unsigned int realloc(unsigned int ptr, unsigned int size);

   unsigned int getHeapBase() {return base;};
   unsigned int getHeapSize() {return max - base;};
   EmuHeap *getNextHeap() {return nextHeap;};
   
   //careful to avoid memory leaks when calling this!
   void setNextHeap(EmuHeap *heap) {nextHeap = heap;};
   
   const MallocNode *heapHead() {return head;};

   void save(Buffer &b);

   static void saveHeapLayout(Buffer &b);
   static void loadHeapLayout(Buffer &b);
   static unsigned int addHeap(unsigned int sz);   //returns hHeap
   static unsigned int destroyHeap(unsigned int hHeap);
   static unsigned int getPrimaryHeap();
   static EmuHeap *getHeap() {return primaryHeap;};
   static EmuHeap *findHeap(unsigned int hHeap);
   static void initHeap(const char *name, unsigned int maxSize = 0x100000);

private:
   EmuHeap(Buffer &b, unsigned int num_blocks);

   bool checkHeapSize(unsigned int newsize);
   MallocNode *findMallocNode(unsigned int addr);
   unsigned int findBlock(unsigned int size);
   void insert(MallocNode *node);
   void readHeap(Buffer &b, unsigned int num_blocks);
   void writeHeap(Buffer &b);
   segment_t *h;
   unsigned int base;
   unsigned int max;
   unsigned int size;
   MallocNode *head;
   EmuHeap *nextHeap;
   static EmuHeap *primaryHeap;
};

void createLegacyHeap(Buffer &b);

#endif

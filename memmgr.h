/*
   Source for x86 emulator IdaPro plugin
   File: memmgr.h
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

#ifndef __MEMMGR_H
#define __MEMMGR_H

#include "x86defs.h"

#define LINUX_PROT_READ       0x1             /* Page can be read.  */
#define LINUX_PROT_WRITE      0x2             /* Page can be written.  */
#define LINUX_PROT_EXEC       0x4             /* Page can be executed.  */
#define LINUX_PROT_NONE       0x0             /* Page can not be accessed.  */
#define LINUX_PROT_GROWSDOWN  0x01000000      /* Extend change to start of
                                           growsdown vma (mprotect only).  */
#define LINUX_PROT_GROWSUP    0x02000000      /* Extend change to start of
                                           growsup vma (mprotect only).  */

/* Sharing types (must choose one and only one of these).  */
#define LINUX_MAP_SHARED      0x01            /* Share changes.  */
#define LINUX_MAP_PRIVATE     0x02            /* Changes are private.  */
#define LINUX_MAP_TYPE       0x0f            /* Mask for type of mapping.  */
#define LINUX_PROT_GROWSDOWN  0x01000000      /* Extend change to start of
                                           growsdown vma (mprotect only).  */
#define LINUX_PROT_GROWSUP    0x02000000      /* Extend change to start of
                                           growsup vma (mprotect only).  */

/* Sharing types (must choose one and only one of these).  */
#define LINUX_MAP_SHARED      0x01            /* Share changes.  */
#define LINUX_MAP_PRIVATE     0x02            /* Changes are private.  */
#define LINUX_MAP_TYPE       0x0f            /* Mask for type of mapping.  */

/* Other flags.  */
#define LINUX_MAP_FIXED       0x10            /* Interpret addr exactly.  */
#define LINUX_MAP_FILE       0
#define LINUX_MAP_ANONYMOUS  0x20            /* Don't use a file.  */
#define LINUX_MAP_ANON       LINUX_MAP_ANONYMOUS

/* These are Linux-specific.  */
#define LINUX_MAP_GROWSDOWN  0x00100         /* Stack-like segment.  */
#define LINUX_MAP_DENYWRITE  0x00800         /* ETXTBSY */
#define LINUX_MAP_EXECUTABLE 0x01000         /* Mark it as an executable.  */
#define LINUX_MAP_LOCKED     0x02000         /* Lock the mapping.  */
#define LINUX_MAP_NORESERVE  0x04000         /* Don't check for reservations.  */
#define LINUX_MAP_POPULATE   0x08000         /* Populate (prefault) pagetables.  */
#define LINUX_MAP_NONBLOCK   0x10000         /* Do not block on IO.  */
#define LINUX_MAP_STACK      0x20000         /* Allocation is for a stack.  */

//for access
#define LINUX_R_OK    4               /* Test for read permission.  */
#define LINUX_W_OK    2               /* Test for write permission.  */
#define LINUX_X_OK    1               /* Test for execute permission.  */
#define LINUX_F_OK    0               /* Test for existence.  */

#define MM_MAP_FIXED LINUX_MAP_FIXED
#define MM_MAP_ANONYMOUS LINUX_MAP_ANONYMOUS

void createNewSegment(const char *name, unsigned int base, unsigned int size);

class MemMgr {
public:
   static void reserve(unsigned int addr, unsigned int size);
   static unsigned int mmap(unsigned int addr, unsigned int size, unsigned int prot, unsigned int flags, const char *segName = NULL);
   static unsigned int mapFixed(unsigned int addr, unsigned int size, unsigned int prot, unsigned int flags, const char *segName = NULL);
   static unsigned int munmap(unsigned int addr, unsigned int size);
};

#endif

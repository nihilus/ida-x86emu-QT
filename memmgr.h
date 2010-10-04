/*
   Source for x86 emulator IdaPro plugin
   File: memmgr.h
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

#ifndef __MEMMGR_H
#define __MEMMGR_H

#include "x86defs.h"

class MemMgr {
public:
   static void reserve(dword addr, dword size);
   static dword mmap(dword addr, dword size, dword prot, dword flags, const char *segName = NULL);
   static dword munmap(dword addr, dword size);
};

#endif

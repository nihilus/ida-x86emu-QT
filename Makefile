#Set this variable to point to your SDK directory
SDKROOT=../../../

#Set this variable to the desired name of your compiled loader
PROC=x86emu

ifndef __LINUX__
PLATFORM_CFLAGS=-D__NT__ -D__IDP__ -DWIN32 -DCYGWIN -Os -mno-cygwin -fno-rtti
PLATFORM_LDFLAGS=--dll -mno-cygwin
IDALIB=$(shell find ../../.. -type d | grep -E "(lib|lib/)gcc.w32")/ida.a
PLUGIN_EXT=.plw
RC=windres
else
PLATFORM_CFLAGS=-D__LINUX__
IDALIB=$(shell find ../../.. -type d | grep -E "(lib|lib/)gcc.lnx")/pro.a
PLUGIN_EXT=.plx
endif

#Platform specific compiler flags
CFLAGS=-Wextra $(PLATFORM_CFLAGS)

#Platform specific ld flags
LDFLAGS=-Wl -shared -s $(PLATFORM_LDFLAGS) 

#specify any additional libraries that you may need
EXTRALIBS=-lcomdlg32 -lgdi32 -luser32 -lpsapi -ladvapi32
RESOURCES=dialog.res

# Destination directory for compiled plugins
OUTDIR=$(SDKROOT)bin/plugins/

#list out the object files in your project here
OBJS=	$(F)x86emu.o \
	$(F)emufuncs.o \
	$(F)cpu.o \
	$(F)emuheap.o \
	$(F)memmgr.o \
	$(F)seh.o \
	$(F)break.o \
	$(F)hooklist.o \
	$(F)buffer.o \
	$(F)emuthreads.o \
	$(F)peutils.o \
	$(F)emu_script.o \
	$(F)context.o \
	$(RESOURCES)

BINARY=$(OUTDIR)$(PROC)$(PLUGIN_EXT)

all: $(OUTDIR) $(BINARY)

clean:
	-@rm *.o
	-@rm $(BINARY)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

CC=g++
INC=-I$(SDKROOT)include/

$(F)%.res: %.rc
	$(RC) -O coff $< $@

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

LD=g++

$(BINARY): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(IDALIB) $(EXTRALIBS) 

#change x86emu below to the name of your plugin, make sure to add any 
#additional files that your plugin is dependent on

x86emu.o: x86emu.cpp break.h emufuncs.h emuthreads.h cpu.h resource.h \
	x86defs.h emuheap.h seh.h hooklist.h peutils.h elf32.h elf_common.h

emufuncs.o: emufuncs.cpp emufuncs.h hooklist.h cpu.h emuheap.h \
	x86defs.h buffer.h

cpu.o: cpu.cpp cpu.h x86defs.h emuheap.h hooklist.h emufuncs.h seh.h \
	buffer.h emuthreads.h

emuheap.o: emuheap.cpp emuheap.h buffer.h

memmgr.o: memmgr.cpp memmgr.h x86defs.h

emuthreads.o: emuthreads.cpp buffer.h cpu.h seh.h x86defs.h

seh.o: seh.cpp cpu.h emuheap.h x86defs.h seh.h x86defs.h

break.o: break.cpp break.h

hooklist.o: hooklist.cpp hooklist.h buffer.h

buffer.o: buffer.cpp buffer.h

peutils.o: peutils.cpp peutils.h buffer.h

dialog.res: dialog.rc resource.h

emu_script.o: emu_script.cpp emu_script.h

context.o: context.cpp context.h

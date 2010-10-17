
#your Ida SDK location either relative to collabreate/trunk
#or absolute
win32:SDK = ..\..\..
unix:SDK = ../../..

#Need to change the following to your Ida install location
win32:IDA_APP = "C:\Program Files\Ida"
linux-g++:IDA_APP = $$(HOME)/ida
macx:IDA_APP = $$(HOME)/ida/idaq.app/Contents

#Need to change the following to your Qt install location
macx:QT_LOC = /usr/local/Trolltech/Qt-4.6.3/lib
macx:QT_TAIL = .framework/Versions/4/Headers
#create our own list of Qt modules
macx:MODS = QtGui QtCore

defineReplace(makeIncludes) {
   variable = $$1
   modules = $$eval($$variable)
   dirs =
   for(module, modules) {
      dir = $${QT_LOC}/$${module}$${QT_TAIL}
      dirs += $$dir
   }
   return($$dirs)
}

TEMPLATE = lib

#QT +=

CONFIG += qt dll

win32-msvc2008:INCLUDEPATH += $${SDK}\include
linux-g++|macx|win32-g++:INCLUDEPATH += $${SDK}/include

win32-msvc2008:DESTDIR = $${SDK}\bin\plugins
linux-g++|macx|win32-g++:DESTDIR = $${SDK}/bin/plugins

DEFINES += __IDP__ __QT__
win32:DEFINES += __NT__ WIN32
win32:DEFINES -= UNICODE
win32-g++:DEFINES += CYGWIN
win32-msvc2008:DEFINES += _CRT_SECURE_NO_WARNINGS
linux-g++:DEFINES += __LINUX__
macx:DEFINES += __MAC__

win32:LIBS += comdlg32.lib gdi32.lib user32.lib advapi32.lib
win32-msvc2008:LIBS += $${SDK}\lib\vc.w32\ida.lib
win32-g++:LIBS += $${SDK}/lib/gcc.w32/ida.a
linux-g++:LIBS += -L$${IDA_APP} -lida
macx:LIBS += -L$${IDA_APP}/MacOs -lida

#don't let qmake force search any libs other than the
#ones that ship with Ida
linux-g++:QMAKE_LFLAGS_RPATH =
linux-g++:QMAKE_LIBDIR_QT =

macx:QMAKE_INCDIR = $$makeIncludes(MODS)
#use Idas QT LIBS unfortuantely this is also added as an include directory
macx:QMAKE_LIBDIR_QT = $${IDA_APP}/Frameworks
#add QTs actual include file location this way since -F is not
#handled by QMAKE_INCDIR
macx:QMAKE_CXXFLAGS += -F$${QT_LOC}

win32-g++:QMAKE_CXXFLAGS -= mthreads

SOURCES = x86emu.cpp \
   x86emu_ui_qt.cpp \
	emufuncs.cpp \
	cpu.cpp \
	emuheap.cpp \
	memmgr.cpp \
	seh.cpp \
	break.cpp \
	hooklist.cpp \
	buffer.cpp \
	emuthreads.cpp \
	peutils.cpp \
	emu_script.cpp \
	context.cpp

HEADERS = break.h \
   bsd_syscalls.h \
   buffer.h \
   context.h \
   cpu.h \
   elf32.h \
   elf_common.h \
   emu_script.h \
   emufuncs.h \
   emuheap.h \
   emuthreads.h \
   hooklist.h \
   linux_syscalls.h \
   memmgr.h \
   peutils.h \
   sdk_versions.h \
   seh.h \
   x86emu_ui_qt.h \
   x86defs.h

win32:TARGET_EXT=.plw
linux-g++:TARGET_EXT=.plx
macx:TARGET_EXT=.pmc

TARGET = x86emu_qt

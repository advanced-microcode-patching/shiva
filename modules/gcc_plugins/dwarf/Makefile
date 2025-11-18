# Makefile for SHIVA GCC plugin (NetBSD-style formatting welcome)
# Makefile for SHIVA GCC plugin (NetBSD-style formatting welcome)

CXX      := g++
CXXFLAGS := -std=c++11 -fPIC -Wall -Wextra -O2 -fno-rtti -fvisibility=hidden
LDFLAGS  := -shared 
TARGET   := shiva_dwarf_plugin.so
SOURCE   := shiva_dwarf_plugin.cc

# --- Path Configuration ---
MUSL_PREFIX     := /usr/local/musl
ELFMASTER_PREFIX:= /opt/elfmaster
GCC_PLUGIN_DIR  := /usr/lib/gcc/x86_64-linux-gnu/11

INC := \
    -I$(MUSL_PREFIX)/include/libdwarf-2 \
    -I$(ELFMASTER_PREFIX)/include \
    -I$(GCC_PLUGIN_DIR)/include \
    -I$(GCC_PLUGIN_DIR)/plugin/include 

# Libraries: Use shared system libraries (-l flags) 
LIBS := -lelf -lz

# Linker search paths (-L flags)
LDFLAGS += -L/usr/lib/x86_64-linux-gnu -L/usr/local/lib

all: $(TARGET)

$(TARGET): $(SOURCE)
	# Force inclusion of all symbols from static archives only using --whole-archive
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(INC) $^ \
	-Wl,--whole-archive $(MUSL_PREFIX)/lib/libdwarf.a $(ELFMASTER_PREFIX)/lib/libelfmaster.a -Wl,--no-whole-archive \
	$(LIBS) -o $@

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean


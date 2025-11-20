#!/bin/bash

# Define paths
MUSL_PREFIX=/usr/local/musl
ELFMASTER_PREFIX=/opt/elfmaster
GCC_DIR=/usr/lib/gcc/x86_64-linux-gnu/11

g++ -DDEBUG -std=c++11 -shared -o shiva_dwarf_plugin.so \
    -fPIC -fno-rtti -fvisibility=hidden \
    -I"${MUSL_PREFIX}/include/libdwarf-2/" \
    -I"${ELFMASTER_PREFIX}/include" \
    -I"${GCC_DIR}/include" \
    -I"${GCC_DIR}/plugin/include" \
    shiva_dwarf_plugin.c \
    -Wl,--whole-archive "${MUSL_PREFIX}/lib/libdwarf.a" "${ELFMASTER_PREFIX}/lib/libelfmaster.a" -Wl,--no-whole-archive \
    -L/usr/lib/x86_64-linux-gnu -L/usr/local/lib \
    -lelf -lz \
    /lib/x86_64-linux-gnu/libc.so.6

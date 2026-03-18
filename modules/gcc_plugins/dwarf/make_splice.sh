#!/bin/sh

# CANNOT USE omit-frame-pointer in this type of splice patch

clang -O0 -g target.c -o target

gcc -fplugin=./shiva_dwarf_plugin.so \
	-fplugin-arg-shiva_dwarf_plugin-elf=./target \
	-fplugin-arg-shiva_dwarf_plugin-insert=0x115c \
	-fplugin-arg-shiva_dwarf_plugin-extend=0x1163 \
	-fplugin-arg-shiva_dwarf_plugin-trace=2 \
	-I ../../include -fno-omit-frame-pointer -fno-stack-protector  -mcmodel=large -c splice.c


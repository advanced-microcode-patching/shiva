gcc -fplugin=./shiva_dwarf_plugin.so  -I ../../include -fno-stack-protector -fomit-frame-pointer -mcmodel=large -c splice.c


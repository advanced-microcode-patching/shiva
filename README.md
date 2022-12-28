# Shiva -- Programmable runtime linking and microcode patching


## Description

Shiva is a programmable runtime linker (Program interpreter) for ELF
x64/aarch64 Linux -- ELF-microprograms (Shiva modules) are linked into the
process address space and given intricate control over program instrumentation
via ShivaTrace API. ShivaTrace is an in-process debugging and instrumentation
API with innovative debugging and hooking features.

Shiva has been custom tailored towards the requirements of the AMP project and
with support for the AArch64 architecture. This fork of the project has created
an abundant set of new microcode patching capabilities, including symbol interposition
on functions (i.e. .text), as well as on global data (i.e. .rodata, .data, .bss).

The original Shiva project can be found at https://github.com/elfmaster/shiva

This README will only cover Shiva as it relates to the AMP project.

Please see ./documentation/shiva_preliminary_design.pdf for a technical description
of Shiva.

## Support

Support is limited to ELF AArch64 ET_DYN binaries. Future support for ET_EXEC will
be added as needed. The cFS software and the patch challenge-10 binaries are
ELF AArch64 ET_DYN binaries, so currently we are meeting the requirements.

## Build

This has been tested on aarch64 ubuntu 18.04 and 22.
Shiva relies on libelfmaster and musl-libc.

## Dependencies


#### libelfmaster (aarch64_support branch)

```
git clone git@github.com:elfmaster/libelfmaster
cd libelfmaster
git --fetch all
git checkout aarch64_support
```

The original build for libelfmaster seems broken and I haven't yet fixed it.
Meanwhile just use the simple build shellscript I made.

```
cd src
sudo make.sh
```

The static library to libelfmaster
```/opt/elfmaster/lib/libelfmaster.a```

The header file to libelfmaster
```/opt/elfmaster/include/elfmaster.h```


#### musl-libc

sudo apt-get install musl musl-dev musl-tools


## Building Shiva

```
cd ~/git
git clone git@github.com:advanced-microcode-patching/shiva
cd shiva
make
make shiva-ld
make patches
sudo make install
```

Shiva is copied to `"/lib/shiva"` and can be executed directly, but more commonly
indirectly as an interpreter.

The shiva-ld utility is used to modify binaries with the path to the new
program interpreter `"/lib/shiva"`, and the path to the patch module (i.e.
`"/opt/modules/shiva/patch1.o"`).

## Patch testing

We have already compiled and prelinked the patches. Shiva prelinking
refers specifically to the Shiva prelinking applied by the shiva-ld tool.

Take a look at the Makefile for each patch, and you will see how shiva-ld is
used to apply the pre-patch meta-data.

```
shiva-ld -e core-cpu1 -p cfs_patch1.o -i /lib/shiva -s /opt/shiva/modules -o core-cpu1.patched
```

The Shiva make install script installs all of the patch modules into `/opt/shiva/modules`

The patch build environments are stored in `modules/aarch64_patches/` and are as follows:

#### cfs_patch1

This is just a simple patch that uses symbol interposition to replace the
STB_GLOBAL/STT_FUNC `OS_printf` that lives within the `core-cpu1` executable.
The patch `cfs_patch1.c` simply rewrites its own version of the function.

The contents of the `./modules/aarch64_patches/cfs_patch1`

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/cfs_patch1$ ls
cfs_patch1.c  cfs_patch1.o  core-cpu1  core-cpu1.patched  EEPROM.DAT  Makefile
```

The program that we are patching is `core-cpu1` and specifically the symbol `OS_printf`

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/cfs_patch1$ readelf -s core-cpu1 | grep OS_printf
   241: 0000000000047d88   456 FUNC    GLOBAL DEFAULT   13 OS_printf
```

Our patch contains it's own version of the function `OS_printf` and at runtime Shiva will load
the `/opt/shiva/modules/cfs_patch1.o` handle all of it's own relocations, and then it will externally
re-link `core-cpu1` so that any calls to the old `OS_printf` are patched to call the new `OS_printf`
that lives within the modules runtime environment setup by Shiva.


```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/cfs_patch1$ cat cfs_patch1.c
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

void OS_printf(const char *string, ...)
{
	char msg_buffer[4096];
	va_list va;
	int sz;

	va_start(va, string);
	sz = vsnprintf(msg_buffer, sizeof(msg_buffer), string, va);
	va_end(va);
	msg_buffer[sz] = '\0';
	printf("[PATCHED :)]: %s\n", msg_buffer); /* NOTICE THIS LINE */
}

```

A quick look at the `PT_INTERP` segment will reveal that core-cpu1.patched has `"/lib/shiva"`
set as the program interpreter.

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/cfs_patch1$ readelf -l core-cpu1.patched | grep interpreter
      [Requesting program interpreter: /lib/shiva]
```

Two custom dynamic segment entries were also added to the binary:

`SHIVA_DT_SEARCH` denotes a dynamic entry containing the address of the module search path,
usually set to `"/opt/shiva/modules/"`.

`SHIVA_DT_NEEDED` denotes a dynamic entry containing the address of the module basename,
i.e. `"cfs_patch1.o"`.

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/cfs_patch1$ readelf -d core-cpu1.patched  | tail -n 3
 0x0000000060000018 (Operating System specific: 60000018)                0x1ab200
 0x0000000060000017 (Operating System specific: 60000017)                0x1ab213
 0x0000000000000000 (NULL)               0x0
```

#### Running core-cpu1.patched












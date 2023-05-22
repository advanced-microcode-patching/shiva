# Shiva JIT micropatching engine


## Description

Shiva is an ELF dynamic linker that is specialized for patching native Linux
software. Shiva has been custom tailored towards the requirements of the DARPA
AMP project and currently supports the AArch64 architecture.

Patches are written in C and compiled into ELF relocatable objects. Shiva loads,
links, and patches the new code into memory.

## Support

OS: Linux
Architectures: AArch64
ELF binary support: AArch64 ELF PIE executables (aka. ET_DYN)

Support for ET_EXEC binaries and other architectures are on the way.

## Build

This has been tested on aarch64 ubuntu 18.04 and ubuntu 22.
Shiva relies on libelfmaster and musl-libc.

## Dependencies


#### libelfmaster (aarch64_support branch)

```
git clone git@github.com:elfmaster/libelfmaster
cd libelfmaster
git --fetch all
git checkout aarch64_support
```

The original build for libelfmaster is broken and I haven't yet fixed it.
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

```
sudo apt-get install musl musl-dev musl-tools
```

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

Shiva is copied to `"/lib/shiva"` and can be executed directly or indirectly as
an interpreter.

The shiva-ld utility is known as the "Shiva Prelinker" and is used to modify
binaries with the path to the new program interpreter `"/lib/shiva"`, and the
path to the patch module (i.e.  `"/opt/modules/shiva/patch1.o"`).

## Patch testing


$ cd modules/aarch64/cfs_patch1

We have already compiled and prelinked the example patches in the previous
steps. Shiva prelinking refers specifically to the prelinking applied by
the shiva-ld tool.

Take a look at the Makefile for each patch, and you will see how shiva-ld is
used to apply the pre-patch meta-data.

```
shiva-ld -e core-cpu1 -p cfs_patch1.o -i /lib/shiva -s /opt/shiva/modules -o core-cpu1.patched
```

The Shiva install script installs all of the patch modules into `/opt/shiva/modules`

The patch build environments are stored in `modules/aarch64_patches/` and are as follows:

### CFS Binary patch: cfs_patch1

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

A quick look at the `PT_INTERP` segment will reveal that `core-cpu1.patched` has `"/lib/shiva"`
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

NOTE: The new dynamic segment lives within a newly created PT_LOAD segment. The new PT_LOAD segment
is the result of a PT_NOTE to PT_LOAD transition.

#### Running core-cpu1.patched


When running the `./core-cpu.patched` we see in the last stdout line our patched
`OS_printf` executes. Notice it prefaces each line of output with the string `"[PATCHED :)]"`

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/cfs_patch1$ ./core-cpu1.patched 
OS_BSP_Initialize():Maximum user msg queue depth = 10
CFE_PSP: Default Reset SubType = 1
CFE_PSP: Default CPU ID = 1
CFE_PSP: Default Spacecraft ID = 66
CFE_PSP: Default CPU Name: cpu1
OS_Posix_GetSchedulerParams():186:Policy 1: available, min-max: 1-99
OS_Posix_GetSchedulerParams():186:Policy 2: available, min-max: 1-99
OS_Posix_TaskAPI_Impl_Init():372:Selected policy 2 for RT tasks, root task = 99
OS_Posix_TaskAPI_Impl_Init():388:Could not setschedparam in main thread: Operation not permitted (1)
CFE_PSP: initializing module 'soft_timebase' with ID 0110ff00
CFE_PSP: Instantiated software timebase 'cFS-Master' running at 10000 usec
CFE_PSP: initializing module 'timebase_posix_clock' with ID 0110ff01
CFE_PSP: Using POSIX monotonic clock as CFE timebase
CFE_PSP: initializing module 'eeprom_mmap_file' with ID 0110ff02
CFE_PSP: Using MMAP simulated EEPROM implementation
[PATCHED :)]: CFE_PSP: EEPROM Range (2) created: Start Address = FFFF84032000, Size = 00080000 Status = 0
```

#### Patching .rodata symbols with Shiva: rodata_interposing patch.

`modules/aarch64_patches/rodata_interposing`

This patch demonstrates how Shiva is able to link new read-only data into place over
existing read-only data symbols. For example


The contents of the `rodata_interposing` directory

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/rodata_interposing$ ls
Makefile  ro_patch.c  ro_patch.o  test_rodata  test_rodata.c  test_rodata.patched
```

The original program has a read-only string `const char rodata_string[] = "Arcana Technologies"`

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/rodata_interposing$ readelf -s test_rodata | grep rodata_string
    73: 0000000000000800    20 OBJECT  GLOBAL DEFAULT   15 rodata_string
```

This constant string data is stored within the `.rodata section`.

```
objdump -D test_rodata | less

...

0000000000000800 <rodata_string>:
 800:   61637241        .word   0x61637241
 804:   5420616e        .word   0x5420616e
 808:   6e686365        .word   0x6e686365
 80c:   676f6c6f        .word   0x676f6c6f
 810:   00736569        .word   0x00736569
```

Our patch aims to change the string from `"Arcana Technologies"` to `"The Great Arcanum"`.

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/rodata_interposing$ cat ro_patch.c

const char rodata_string[] = "The Great Arcanum";

```

The compiled patch is `ro_patch.o`

At runtime Shiva will load and link the patch with the executable in memory, and all references
to the old `rodata_string[]` will be replaced with the correct offset to the patches version of
`rodata_string[]`. The original string is not being over-written, but is no longer referenced.


#### Running the unpatched and patched test_rodata binary

```
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/rodata_interposing$ ./test_rodata
rodata_string: Arcana Technologies
val: 5
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/rodata_interposing$ ./test_rodata.patched
rodata_string: The Great Arcanum
val: 5
elfmaster@esoteric-aarch64:~/amp/shiva/modules/aarch64_patches/rodata_interposing$ 
```

### Work in progress

This README is a work in progress. A "Friendly guide to micropatching with Shiva" User manual
will be available soon!


### Author contact

Ryan O'Neill
ryan@bitlackeys.org


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

The patches are stored in `modules/aarch64_patches/`












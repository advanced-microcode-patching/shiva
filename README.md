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

This has been tested on aarch64 ubuntu 18.04 and 22. Shiva uses the code from
the https://github.com/elfmaster/libelfmaster project, specifically a custom
aarch64 branch.

Shiva also relies on musl-libc to avoid a problem with glibc's initialization code
which is not compatible with Shiva running as an interpreter. (See custom_interp_notes.txt)

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

The static libary will be written to /opt/elfmaster/lib/libelfmaster.a
The header file will be /opt/elfmaster/include/elfmaster.h


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

Shiva is copied to "/lib/shiva" and can be executed directly, but more commonly
indirectly as an interpreter.

## Testing the patches







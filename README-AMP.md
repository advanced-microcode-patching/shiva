- README file for Shiva (From AMP phase-2)

This collection of files is from the DARPA Assured micropatching (AMP)
program. This README provides a basic description of the AMP program
and the overall manifest and description for each file.


---- Assured Micropatching Program

The AMP program is a DARPA effort to develop technologies for advancing
the state of patching ELF binaries and verifying the stability of the
patch that has been applied. The AMP program can be found here
https://www.darpa.mil/program/assured-micropatching

DARPA is releasing these files in the public domain to stimulate further
research. Their release implies no obligation or desire to support additional
work in this space. The data is released as-is. DARPA makes no warranties as
to the correctness, accuracy, or usefulness of the released data. In fact,
since the data was produced by a research prototype, it is practically guaranteed
to be imperfect.


---- Description of Shiva

Shiva was a phase-2 effort to advance the state of ELF binary patching by
introducing a custom ELF interpreter for loading and linking ELF relocatable
objects into the process image at runtime. Shiva aims to make patch development
a seamless process, fitting right into the existing ELF ABI toolchain of
compilers and linkers. Shiva supports Linux AArch64 environments.

---- Github location

Shiva's github home is at https://github.com/advanced-microcode-patching/shiva

---- File descriptions

README-AMP.md: This file
README.md: File describing how to build and use Shiva
documentation/shiva_final_design.pdf: A document describing the internal design of Shiva
libcapstone.a: A pre-built static library of the Capstone API
modules/aarch64_patches/cfs_patch1/core-cpu1: A binary built from NASA cSF github repository to test patching against
modules/aarch64/amp_challenge10/program_c: An aarch64 binary taken from the beaglebone, as a patch challenge for AMP
include/capstone: Header files from capstone disassembly API


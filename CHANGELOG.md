# Shiva CHANGELOG

## v0.11 Alpha - 8/13/2023

* First public release of Shiva


## v0.12 Alpha - 10/2/2023

* Finished Shiva Prelinker v2.0 (That's the "/usr/bin/shiva-ld" tool)
	- See ticket: https://github.com/advanced-microcode-patching/shiva/issues/1
	- Performance enhancements of up to 3000% tested
	- Performance enhancement grows proportionate to size of .text section of executable
	- --disable-cfg-gen flag which disables the new control-flow meta-data from shiva-ld
* Updated the Shiva user manual: documentation/shiva_user_manual.pdf to v0.12 Alpha.
* Extended Shiva's shiva_analyze.c code to support consumption of .shiva.xref and .shiva.branch sections.
* Several incidental build changes the patches in modules/aarch64_patches
* Added this CHANGELOG to the project.

elfmaster [at] arcana-research.io

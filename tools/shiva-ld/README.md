# Shiva Prelinker "/bin/shiva-ld"

## Compile

make
sudo make install

## Example: A patch for an .rodata string

#### modules/aarch64_patches/rodata_interposing/test_rodata.c
```
#include <stdio.h>

const char rodata_string[] = "Arcana Technologies";

const int val = 5;

int main(void)
{
	printf("rodata_string: %s\n", rodata_string);
	printf("val: %d\n", 5);
}

```

If we simply want to patch `rodata_string[]`, we can write a very
natural patch in C

#### modules/aarch64_patches/rodata_interposing/ro_patch.c

```
const char rodata_string[] = "The Great Arcanum";
```

At runtime Shiva will actually relink the executable so that all references
to the original .rodata string are replaced with offsets to the new .rodata
value within the modules runtime environment. In other words the original
.rodata string is not over-written, it is simply abandoned.


### Shiva prelinking

The Shiva prelinker does not apply the actual patch. It simply inserts enough
meta-data into the executable so that it can locate and load the patch at
runtime.  Shiva-ld will modify the ELF executable PT_INTERP segment and replace
"/lib/aarch64-ld-linux.so" with "/lib/shiva" therefore invoking Shiva as the
program interpreter at runtime.  Shiva will look for an updated dynamic segment
containing custom PT_DYNAMIC tags describing the patch location. Shiva-ld
creates a new and updated PT_DYNAMIC segment within a new PT_LOAD segment as
part of the prelinking process.

#### Custom Dynamic tags for the Shiva interpreter

```
#define SHIVA_DT_NEEDED (DT_LOOS + 10) // Patch basename (i.e. "patch.o")
#define SHIVA_DT_SEARCH (DT_LOOS + 11) // Search path (i.e. "/opt/shiva/modules")
#define SHIVA_DT_ORIG_INTERP (DT_LOOS + 12) // Original interpreter path (i.e. "/lib/ld-linux.so")
```

#### Using shiva-ld command line tool

The Shiva prelinker is called "/usr/bin/shiva-ld" and has the following command line
usage:

```
Usage: shiva-ld -e test_bin -p patch1.o -i /lib/shiva-s /opt/shiva/modules/ -o test_bin_final
[-e] --input_exec	Input ELF executable
[-p] --input_patch	Input ELF patch
[-i] --interp_path	Interpreter search path, i.e. "/lib/shiva"
[-s] --search_path	Module search path (For patch object)
[-o] --output_exec	Output executable
```

Prelink the executable "vuln_program". Don't forget to copy patch.o into the search
path specified to shiva-ld; in our case "/opt/shiva/modules". This is akin to how
shared libraries are typically stored in /lib/x86-64-linux.gnu/

```
$ shiva-ld -e ./vuln_program -p patch.o -i /lib/shiva -s /opt/shiva/modules -o ./vuln_program
$ sudo cp patch.o /opt/shiva/modules
```

elfmaster@arcana-research.io

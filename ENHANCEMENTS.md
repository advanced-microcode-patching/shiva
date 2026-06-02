## Shiva enhancements

This is a list of enhancements. Some of them have been implemented, some have not.

### Function splicing

1. Preserve and restore the registers that are used in a splice.

When splicing code into an existing function, the splice code is compiled with code
that may corrupt one or more registers that are used by the code directly before and
directly after the splice. It would be a nice feature if the compiler can instrument
the splice prologue with necessary push/pop instructions for preserving the register
state.

2. DWARF aware function splicing 
(Partially finished: Splice by line-number is available)

Shiva uses specialized macros to generate the code for a function splice. Currently
the macro requires that the developer knows which memory addresses to place the splice
between which requires a reverse engineering effort. In an ideal world Shiva would still
allow this, but would also offer the ability for users to specify the patch by line numbers.

3. Add support for multiple splices in a single function 
(STATUS: Unfinished)

Currently Shiva does not allow for more than one splice per function. You cannot splice
into two separate places within the same function. You can however splice into multiple functions,
as long as each function only has one splice. In the future functions should allow for multiple
function splicing.

4. Function splicing on inlined functions is hard with Shiva
(STATUS: Unfinished)

Currently to splice an inlined function with Shiva the patch developer must create a splice
into the parent function of the inlined function.

5. DWARF aware local var resolution in function splices, to access function args and local vars by name
(STATUS: Partially done. Research and code about 30% complete)

Currently in a function splice Shiva offers macros that use keywords and assembly instructions
to pair registers to a stack variable or function argument. For example if a pointer was stored
in register RDI as a function argument, a splice early on in the function might access it with
the SHIVA_T_PAIR_RDI macro.

```
SHIVA_T_PAIR_RDI(arg1);
printf("Arg1 ptr value: %p\n", (void *)arg1);
```

This macro is simple and nice, but still requires that the patch developer knows which register
to use. It would be nice if the developer could reference a stack variable or argument by name
via symbolic DWARF data.

### Enhancements not specific to function splicing

1. Symbol interposition on STB_LOCAL functions
(STATUS: Partially. I haven't merged the branch in yet)

Shiva needs better support for interposing (And splicing) static functions. statically declared
functions have STB_LOCAL symbol bindings. Shiva support is not well tested for STB_LOCAL.

2. Symbol interposition on inlined functions
(STATUS: Unfinished)

Currently the only way to patch an inlined function with Shiva is to use a function splice that
patches the parent function of the inlined function. There is no way to specify the inlined function
by symbol name. This should work by Shiva figuring out where the function has been inlined too and
then create a trampoline to the new version of the inlined function.

3. Consume .rela.text section
(STATUS: Unfinished, but an example of this is implemented in modules/gASLR.c)

This would speed up re-linking the executable to the interposed code and data. It will not speed up
Shiva in the event of function splicing though. Item 4 (Below) can be implemented as it is in AArch64 Shiva,
to speed up re-linking in all respects for x86_64.

4. x86_64 Shiva should generate custom ELF sections containing control flow and xref information
(STATUS: finished as apart of DARPA EBOSS work)

Currently all control flow analysis is done at runtime in x86_64 slowing Shiva down. In AArch64 Shiva
the shiva-ld utility generates 2 custom ELF sections containing branch and xref information that Shiva
consumes at runtime greatly speeding up re-linking all the way around.

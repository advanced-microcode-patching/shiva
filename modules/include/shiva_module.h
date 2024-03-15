/*
 * shiva_module.h contains the transform macros and other
 * helper code that is used by shiva modules.
 */
#include <stdint.h>

/*
 * These are the mnemonics for identifying the function
 * name, and the patch start/end address.
 */
#define SHIVA_T_SPLICE_FUNC_ID "__shiva_splice_fn_name_"
#define SHIVA_T_SPLICE_INSERT_ID "__shiva_splice_insert_"
#define SHIVA_T_SPLICE_EXTEND_ID "__shiva_splice_extend_"

#define SHIVA_T_SPLICE_FUNCTION(fn_name, insert, extend)	\
	static uint64_t __shiva_splice_insert_##fn_name __attribute__((section(".shiva.transform"))) = insert; \
	static uint64_t __shiva_splice_extend_##fn_name __attribute__((section(".shiva.transform"))) = extend; \
	void * __attribute__((naked)) __shiva_splice_fn_name_##fn_name(void)

#ifdef __x86_64__

#define SHIVA_T_PAIR_RAX(var) register int64_t var asm("rax");
#define SHIVA_T_PAIR_RBX(var) register int64_t var asm("rbx");
#define SHIVA_T_PAIR_RDI(var) register int64_t var asm("rdi");
#define SHIVA_T_PAIR_RSI(var) register int64_t var asm("rsi");
#define SHIVA_T_PAIR_RCX(var) register int64_t var asm("rcx");
#define SHIVA_T_PAIR_RDX(var) register int64_t var asm("rdx");
#define SHIVA_T_PAIR_R8(var)  register int64_t var asm("r8");
#define SHIVA_T_PAIR_R9(var)  register int64_t var asm("r9");
#define SHIVA_T_PAIR_R10(var) register int64_t var asm("r10");
#define SHIVA_T_PAIR_R11(var) register int64_t var asm("r11");
#define SHIVA_T_PAIR_R12(var) register int64_t var asm("r12");

#define SHIVA_T_LEA_BP_4(var)   register int64_t var;   \
                                asm volatile ("lea 4(%%rbp), %0" : "=g"(var));
#define SHIVA_T_LEA_BP_8(var)	register int64_t var;	\
				asm volatile ("lea 8(%%rbp), %0" : "=g"(var));
#define SHIVA_T_LEA_BP_16(var)	register int64_t var;	\
				asm volatile ("lea 16(%%rbp), %0" : "=g"(var));
#define SHIVA_T_LEA_BP_24(var)	register int64_t var;	\
				asm volatile ("lea 24(%%rbp), %0" : "=g"(var));
#define SHIVA_T_LEA_BP_32(var)	register int64_t var;	\
				asm volatile ("lea 32(%%rbp), %0" : "=g"(var));



#elif __aarch64__

#define SHIVA_T_PAIR_X0(var) register int64_t var asm("x0");
#define SHIVA_T_PAIR_X1(var) register int64_t var asm("x1");
#define SHIVA_T_PAIR_X2(var) register int64_t var asm("x2");
#define SHIVA_T_PAIR_X3(var) register int64_t var asm("x3");
#define SHIVA_T_PAIR_X4(var) register int64_t var asm("x4");
#define SHIVA_T_PAIR_X5(var) register int64_t var asm("x5");
#define SHIVA_T_PAIR_X6(var) register int64_t var asm("x6");
#define SHIVA_T_PAIR_X7(var) register int64_t var asm("x7");

#define SHIVA_T_PAIR_X8(var) register int64_t var asm("x8");
#define SHIVA_T_PAIR_X9(var) register int64_t var asm("x9");
#define SHIVA_T_PAIR_X10(var) register int64_t var asm("x10");
#define SHIVA_T_PAIR_X11(var) register int64_t var asm("x11");
#define SHIVA_T_PAIR_X12(var) register int64_t var asm("x12");
#define SHIVA_T_PAIR_X13(var) register int64_t var asm("x13");
#define SHIVA_T_PAIR_X14(var) register int64_t var asm("x14");
#define SHIVA_T_PAIR_X15(var) register int64_t var asm("x15");
#define SHIVA_T_PAIR_X16(var) register int64_t var asm("x16");
#define SHIVA_T_PAIR_X17(var) register int64_t var asm("x17");
#define SHIVA_T_PAIR_X18(var) register int64_t var asm("x18");
#define SHIVA_T_PAIR_X19(var) register int64_t var asm("x19");
#define SHIVA_T_PAIR_X20(var) register int64_t var asm("x20");
#define SHIVA_T_PAIR_X21(var) register int64_t var asm("x21");
#define SHIVA_T_PAIR_X22(var) register int64_t var asm("x22");
#define SHIVA_T_PAIR_X23(var) register int64_t var asm("x23");
#define SHIVA_T_PAIR_X24(var) register int64_t var asm("x24");
#define SHIVA_T_PAIR_X25(var) register int64_t var asm("x25");
#define SHIVA_T_PAIR_X26(var) register int64_t var asm("x26");
#define SHIVA_T_PAIR_X27(var) register int64_t var asm("x27");
#define SHIVA_T_PAIR_X28(var) register int64_t var asm("x28");


#define SHIVA_T_PAIR_W0(var) register int64_t var asm("w0");
#define SHIVA_T_PAIR_W1(var) register int64_t var asm("w1");
#define SHIVA_T_PAIR_W2(var) register int64_t var asm("w2");
#define SHIVA_T_PAIR_W3(var) register int64_t var asm("w3");
#define SHIVA_T_PAIR_W4(var) register int64_t var asm("w4");
#define SHIVA_T_PAIR_W5(var) register int64_t var asm("w5");
#define SHIVA_T_PAIR_W6(var) register int64_t var asm("w6");
#define SHIVA_T_PAIR_W7(var) register int64_t var asm("w7");


/*
 * XXX
 * The following macros use register x9. This means you can't use
 * more than one macro at a time without clobbering x9.
 *
 * In the future: Allow the developer to select the register as it
 * greatly depends on the function being transformed.
 */

#define SHIVA_T_PAIR_BP_4(var) asm volatile ("ldr x9, [x29, #4]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_8(var) asm volatile ("ldr x9, [x29, #8]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_16(var) asm volatile ("ldr x9, [x29, #16]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_24(var) asm volatile ("ldr x9, [x29, #24]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_32(var) asm volatile ("ldr x9, [x29, #32]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_40(var) asm volatile ("ldr x9, [x29, #40]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_48(var) asm volatile ("ldr x9, [x29, #48]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_56(var) asm volatile ("ldr x9, [x29, #56]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_64(var) asm volatile ("ldr x9, [x29, #64]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_72(var) asm volatile ("ldr x9, [x29, #64"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_80(var) asm volatile ("ldr x9, [x29, #80]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_88(var) asm volatile ("ldr x9, [x29, #88]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_96(var) asm volatile ("ldr x9, [x29, #96]"); \
				  register int64_t var asm("x9");


#define SHIVA_T_LEA_BP_16(var) asm volatile ("mov x9, x29\n" \
					     "add x9, x9, #16"); \
				register int64_t var asm("x9");

#define SHIVA_T_LEA_BP_24(var) asm volatile ("mov x9, x29\n" \
					     "add x9, x9, #24"); \
				register int64_t var asm("x9");

#define SHIVA_T_LEA_BP_32(var) asm volatile ("mov x9, x29\n" \
					     "add x9, x9, #32"); \
				register int64_t var asm("x9");

#define SHIVA_T_LEA_BP_40(var) asm volatile ("mov x9, x29\n" \
					     "add x9, x9, #40"); \
				register int64_t var asm("x9");

#define SHIVA_T_LEA_BP_48(var) asm volatile ("mov x9, x29\n" \
					     "add x9, x9, #48"); \
				register int64_t var asm("x9");

#define SHIVA_T_LEA_BP_56(var) asm volatile ("mov x9, x29\n" \
					     "add x9, x9, #54"); \
				register int64_t var asm("x9");

#define SHIVA_T_LEA_BP_96(var) asm volatile ("mov x9, x29\n"   \
					     "add x9, x9, #96"); \
			        register int64_t var asm("x9");

#define SHIVA_T_PUSH64_X0	asm volatile ("str x0, [sp, #-8]!");
#define SHIVA_T_POP64_X0	asm volatile ("ldr x0, [sp], #8");

#define SHIVA_T_PUSH64_X1	asm volatile ("str x1, [sp, #-8]!");
#define SHIVA_T_POP64_X1	asm volatile ("ldr x1, [sp], #8");

#define SHIVA_T_PUSH64_X2	asm volatile ("str x2, [sp, #-8]!");
#define SHIVA_T_POP64_X2	asm volatile ("ldr x2, [sp], #8");

#define SHIVA_T_PUSH64_X3	asm volatile ("str x3, [sp, #-8]!");
#define SHIVA_T_POP64_X3	asm volatile ("ldr x3, [sp], #8");

#define SHIVA_T_PUSH64_X4	asm volatile ("str x4, [sp, #-8]!");
#define SHIVA_T_POP64_X4	asm volatile ("ldr x4, [sp], #8");

#define SHIVA_T_PUSH64_X5	asm volatile ("str x5, [sp, #-8]!");
#define SHIVA_T_POP64_X5	asm volatile ("ldr x5, [sp], #8");

#define SHIVA_T_PUSH64_X6	asm volatile ("str x6, [sp, #-8]!");
#define SHIVA_T_POP64_X6	asm volatile ("ldr x6, [sp], #8");

#define SHIVA_T_PUSH64_X7	asm volatile ("str x7, [sp, #-8]!");
#define SHIVA_T_POP64_X7	asm volatile ("ldr x7, [sp], #8");

#define SHIVA_T_PUSH64_X8	asm volatile ("str x8, [sp, #-8]!");
#define SHIVA_T_POP64_X8	asm volatile ("ldr x8, [sp], #8");

#define SHIVA_T_PUSH64_X9	asm volatile ("str x9, [sp, #-8]!");
#define SHIVA_T_POP64_X9	asm volatile ("ldr x9, [sp], #8");

#define SHIVA_T_PUSH64_X10	 asm volatile ("str x10, [sp, #-8]!");
#define SHIVA_T_POP64_X10	 asm volatile ("ldr x10, [sp], #8");

#define SHIVA_T_PUSH64_X11	 asm volatile ("str x11, [sp, #-8]!");
#define SHIVA_T_POP64_X11	 asm volatile ("ldr x11, [sp], #8");

#define SHIVA_T_PUSH64_X12	 asm volatile ("str x12, [sp, #-8]!");
#define SHIVA_T_POP64_X12	 asm volatile ("ldr x12, [sp], #8");

#define SHIVA_T_PUSH64_X13	 asm volatile ("str x13, [sp, #-8]!");
#define SHIVA_T_POP64_X13	 asm volatile ("ldr x13, [sp], #8");

#define SHIVA_T_PUSH64_X14	 asm volatile ("str x14, [sp, #-8]!");
#define SHIVA_T_POP64_X14	 asm volatile ("ldr x14, [sp], #8");

#define SHIVA_T_PUSH64_X15	 asm volatile ("str x15, [sp, #-8]!");
#define SHIVA_T_POP64_X15	 asm volatile ("ldr x15, [sp], #8");

#define SHIVA_T_PUSH64_X16	 asm volatile ("str x16, [sp, #-8]!");
#define SHIVA_T_POP64_X16	 asm volatile ("ldr x16, [sp], #8");

#define SHIVA_T_PUSH64_X17	 asm volatile ("str x17, [sp, #-8]!");
#define SHIVA_T_POP64_X17	 asm volatile ("ldr x17, [sp], #8");

#define SHIVA_T_PUSH64_X18	 asm volatile ("str x18, [sp, #-8]!");
#define SHIVA_T_POP64_X18	 asm volatile ("ldr x18, [sp], #8");

#define SHIVA_T_PUSH64_X19	 asm volatile ("str x19, [sp, #-8]!");
#define SHIVA_T_POP64_X19	 asm volatile ("ldr x19, [sp], #8");

#define SHIVA_T_PUSH64_X20	 asm volatile ("str x20, [sp, #-8]!");
#define SHIVA_T_POP64_X20	 asm volatile ("ldr x20, [sp], #8");

#define SHIVA_T_PUSH64_X21	 asm volatile ("str x21, [sp, #-8]!");
#define SHIVA_T_POP64_X21	 asm volatile ("ldr x21, [sp], #8");

#define SHIVA_T_PUSH64_X22	 asm volatile ("str x22, [sp, #-8]!");
#define SHIVA_T_POP64_X22	 asm volatile ("ldr x22, [sp], #8");

#define SHIVA_T_PUSH64_X23	 asm volatile ("str x23, [sp, #-8]!");
#define SHIVA_T_POP64_X23	 asm volatile ("ldr x23, [sp], #8");

#define SHIVA_T_PUSH64_X24	 asm volatile ("str x24, [sp, #-8]!");
#define SHIVA_T_POP64_X24	 asm volatile ("ldr x24, [sp], #8");

#define SHIVA_T_PUSH64_X25	 asm volatile ("str x25, [sp, #-8]!");
#define SHIVA_T_POP64_X25	 asm volatile ("ldr x25, [sp], #8");

#define SHIVA_T_PUSH64_X26	 asm volatile ("str x26, [sp, #-8]!");
#define SHIVA_T_POP64_X26	 asm volatile ("ldr x26, [sp], #8");

#define SHIVA_T_PUSH64_X27	 asm volatile ("str x27, [sp, #-8]!");
#define SHIVA_T_POP64_X27	 asm volatile ("ldr x27, [sp], #8");

#define SHIVA_T_PUSH64_X28	 asm volatile ("str x28, [sp, #-8]!");
#define SHIVA_T_POP64_X28	 asm volatile ("ldr x28, [sp], #8");

#endif

/*
 * Macros for various shiva helpers, namely the CALL_EXTERNAL
 * helper which allows a patched function, say 'foo()' to call
 * the original version of itself: foo(), from the original binary.
 */
#define SHIVA_HELPER_CALL_EXTERNAL_ID "__shiva_helper_orig_func_"

#define SHIVA_HELPER_CALL_EXTERNAL(name)	\
	__shiva_helper_orig_func_##name();

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS1(name, arg1)	\
	__shiva_helper_orig_func_##name(arg1);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS2(name, arg1, arg2)	\
	__shiva_helper_orig_func_##name(arg1, arg2);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS3(name, arg1, arg2)	\
	__shiva_helper_orig_func_##name(arg1, arg2, arg3)

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS4(name, arg1, arg2, arg3, arg4)	      \
	__shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS5(name, arg1, arg2, arg3, arg4, arg5)  \
	__shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4, arg5);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS6(name, arg1, arg2, arg3, arg4, arg5, arg6)  \
	__shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4, arg5, arg6);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS7(name, arg1, arg2, arg3, arg4, arg5, arg6, arg7)  \
	__shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4, arg5, arg6, arg7);









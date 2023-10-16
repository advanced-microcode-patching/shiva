
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
	void * __shiva_splice_fn_name_##fn_name(void)

#define SHIVA_T_PAIR_X0(var) register int64_t var asm("x0");
#define SHIVA_T_PAIR_X1(var) register int64_t var asm("x1");
#define SHIVA_T_PAIR_X2(var) register int64_t var asm("x2");
#define SHIVA_T_PAIR_X3(var) register int64_t var asm("x3");
#define SHIVA_T_PAIR_X4(var) register int64_t var asm("x4");
#define SHIVA_T_PAIR_X5(var) register int64_t var asm("x5");
#define SHIVA_T_PAIR_X6(var) register int64_t var asm("x6");
#define SHIVA_T_PAIR_X7(var) register int64_t var asm("x7");

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

#define SHIVA_HELPER_CALL_EXTERNAL_ID "__shiva_helper_orig_func_"

#define SHIVA_HELPER_CALL_EXTERNAL(name)	\
	__shiva_helper_orig_func_##name();

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS1(name, arg1)	\
	__shiva_helper_orig_func_##name(arg1);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS2(name, arg1, arg2)	\
	__shiva_helper_orig_func_##name(arg1, arg2);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS3(name, arg1, arg2)	\
	__shiva_helper_orig_func_##name(arg1, arg2, arg3)

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS4(name, arg1, arg2, arg3, arg4)        \
        __shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS5(name, arg1, arg2, arg3, arg4, arg5)  \
        __shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4, arg5);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS6(name, arg1, arg2, arg3, arg4, arg5, arg6)  \
        __shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4, arg5, arg6);

#define SHIVA_HELPER_CALL_EXTERNAL_ARGS7(name, arg1, arg2, arg3, arg4, arg5, arg6, arg7)  \
        __shiva_helper_orig_func_##name(arg1, arg2, arg3, arg4, arg5, arg6, arg7);









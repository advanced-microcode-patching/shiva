
#include <stdint.h>

/*
 * In the future we will use clang/gcc plugin to create custom attributes
 * to generate the ptd data.
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

#define SHIVA_T_PAIR_BP_16(var) asm volatile ("ldr x9, [x29, #16]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_32(var) asm volatile ("ldr x9, [x29, #32]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_48(var) asm volatile ("ldr x9, [x29, #48]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_64(var) asm volatile ("ldr x9, [x29, #64]"); \
				  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_80(var) asm volatile ("ldr x9, [x29, #80]"); \
                                  register int64_t var asm("x9");
#define SHIVA_T_PAIR_BP_96(var) asm volatile ("ldr x9, [x29, #96]"); \
                                  register int64_t var asm("x9");


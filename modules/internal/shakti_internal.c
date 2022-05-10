
void __attribute__((naked)) shakti_store_regs_x86_64(struct shiva_trace_regset_x86_64 *regs)
{
        __asm__ __volatile__(
                "movq %rax, (%rdi)\n\t"
                "movq %rbx, 8(%rdi)\n\t"
                "movq %rcx, 16(%rdi)\n\t"
                "movq %rdx, 24(%rdi)\n\t"
                "movq %rsi, 32(%rdi)\n\t"
                "movq %r8,  48(%rdi)\n\t"
                "movq %r9,  56(%rdi)\n\t"
                "movq %r10, 64(%rdi)\n\t"
                "movq %r11, 72(%rdi)\n\t"
                "movq %r12, 80(%rdi)\n\t"
                "movq %r13, 88(%rdi)\n\t"
                "movq %r14, 96(%rdi)\n\t"
                "movq %r15, 104(%rdi)\n\t"
                "ret\n\t"
                );
}


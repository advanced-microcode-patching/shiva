
_start() {
asm volatile("movq $0x5f0007fe0, %rax\n"
	     "push %rax\n"
		"ret");
}

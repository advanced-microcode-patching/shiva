	.file	"fsplice_patch.c"
	.text
	.globl	data_val
	.data
	.align 4
	.type	data_val, @object
	.size	data_val, 4
data_val:
	.long	7
	.section	.shiva.transform,"aw"
	.align 8
	.type	__shiva_splice_insert_foo, @object
	.size	__shiva_splice_insert_foo, 8
__shiva_splice_insert_foo:
	.quad	4539
	.align 8
	.type	__shiva_splice_extend_foo, @object
	.size	__shiva_splice_extend_foo, 8
__shiva_splice_extend_foo:
	.quad	4566
	.section	.rodata
.LC0:
	.string	"Printing str: %s\n"
.LC1:
	.string	"global_buf: %s\n"
	.text
	.globl	__shiva_splice_fn_name_foo
	.type	__shiva_splice_fn_name_foo, @function
__shiva_splice_fn_name_foo:
.LFB0:
	.cfi_startproc
	endbr64
.L3:
	leaq	.L3(%rip), %rbx
	movabsq	$_GLOBAL_OFFSET_TABLE_-.L3, %r11
	addq	%r11, %rbx
#APP
# 25 "fsplice_patch.c" 1
	mov -0x16(%rbp), %r15
# 0 "" 2
#NO_APP
	movq	%r15, %rax
	testq	%rax, %rax
	je	.L2
	movq	%r15, %rdx
	movabsq	$stdout@GOT, %rax
	movq	(%rbx,%rax), %rax
	movq	(%rax), %rax
	movabsq	$.LC0@GOTOFF, %rcx
	leaq	(%rbx,%rcx), %rcx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	movq	%rbx, %r15
	movl	$0, %eax
	movabsq	$fprintf@PLTOFF, %rcx
	addq	%rbx, %rcx
	call	*%rcx
.L2:
	movabsq	$stdout@GOT, %rax
	movq	(%rbx,%rax), %rax
	movq	(%rax), %rax
	movabsq	$global_buf@GOT, %rdx
	movq	(%rbx,%rdx), %rdx
	movabsq	$.LC1@GOTOFF, %rcx
	leaq	(%rbx,%rcx), %rcx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	movq	%rbx, %r15
	movl	$0, %eax
	movabsq	$fprintf@PLTOFF, %rcx
	addq	%rbx, %rcx
	call	*%rcx
	movabsq	$bar@GOTOFF, %rax
	leaq	(%rbx,%rax), %rax
	call	*%rax
	nop
	ud2
	.cfi_endproc
.LFE0:
	.size	__shiva_splice_fn_name_foo, .-__shiva_splice_fn_name_foo
	.section	.rodata
	.align 8
.LC2:
	.string	"I am the new bar, and I am here to say data_val = %d\n"
	.text
	.globl	bar
	.type	bar, @function
bar:
.LFB1:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	subq	$8, %rsp
	.cfi_offset 15, -24
.L5:
	leaq	.L5(%rip), %rdx
	movabsq	$_GLOBAL_OFFSET_TABLE_-.L5, %r11
	addq	%r11, %rdx
	movabsq	$data_val@GOTOFF, %rax
	movl	(%rdx,%rax), %eax
	leal	1(%rax), %ecx
	movabsq	$data_val@GOTOFF, %rax
	movl	%ecx, (%rdx,%rax)
	movabsq	$data_val@GOTOFF, %rax
	movl	(%rdx,%rax), %eax
	movl	%eax, %esi
	movabsq	$.LC2@GOTOFF, %rax
	leaq	(%rdx,%rax), %rax
	movq	%rax, %rdi
	movq	%rdx, %r15
	movl	$0, %eax
	movabsq	$printf@PLTOFF, %rcx
	addq	%rdx, %rcx
	call	*%rcx
	nop
	movq	-8(%rbp), %r15
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	bar, .-bar
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:

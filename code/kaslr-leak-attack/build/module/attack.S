#include <linux/linkage.h>

.text
.global drain_rsb

SYM_FUNC_START(drain_rsb)
	.intel_syntax noprefix

	lea rax, [ret_loop]

	// 32 pushes, because my CPU has 32 RSB entries
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	
	// Return to qemu and re-fill the rsb
	mov al, 0x41
	out 0xe9, al
	
	ret_loop:
		clflush [rsp]
		mfence
		ret

	.att_syntax prefix
SYM_FUNC_END(drain_rsb)

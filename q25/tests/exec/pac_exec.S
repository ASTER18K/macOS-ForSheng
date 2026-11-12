// SPDX-License-Identifier: MIT
// Freestanding AArch64 Linux program that exercises every pointer
// authentication instruction form handled by pac_neutralize.py.
// It is a valid PAC program: every authenticated pointer is signed first, so
// it runs unmodified on a CPU with FEAT_PAuth and, after rewriting, on a CPU
// without it. Exit status 0 and the text "ALL OK" mean every check passed;
// otherwise the exit status is the number of the failing check.

	.text

.macro	FAIL n
	mov	x0, #\n
	b	fail
.endm

#ifdef AS_FUNCTION
// Built into the trap-and-emulate harness: long pac_body(void) returns 0 or
// the number of the failing check.
	.globl	pac_body
	.type	pac_body, %function
pac_body:
	stp	x29, x30, [sp, #-16]!
#else
	.globl	_start
_start:
#endif
	// 1: HINT-space pair in a leaf function
	bl	leaf_hint
	cmp	x0, #1
	b.eq	1f
	FAIL	1
1:
	// 2: PACIBSP + RETAB, 3: PACIASP + RETAA
	bl	leaf_retab
	cmp	x0, #2
	b.eq	1f
	FAIL	2
1:	bl	leaf_retaa
	cmp	x0, #3
	b.eq	1f
	FAIL	3
1:
	// 4: PACIZA + BLRAAZ
	adr	x9, leaf_plain
	paciza	x9
	blraaz	x9
	cmp	x0, #42
	b.eq	1f
	FAIL	4
1:
	// 5: PACIA + BLRAA with a modifier, 6: PACIB + BLRAB
	adr	x9, leaf_plain
	mov	x10, #0x1234
	pacia	x9, x10
	mov	x0, #0
	blraa	x9, x10
	cmp	x0, #42
	b.eq	1f
	FAIL	5
1:	adr	x9, leaf_plain
	mov	x10, sp
	pacib	x9, x10
	mov	x0, #0
	blrab	x9, x10
	cmp	x0, #42
	b.eq	1f
	FAIL	6
1:
	// 7: PACIZB + BLRABZ
	adr	x9, leaf_plain
	pacizb	x9
	mov	x0, #0
	blrabz	x9
	cmp	x0, #42
	b.eq	1f
	FAIL	7
1:
	// 8..11: BRAAZ, BRABZ, BRAA, BRAB used as tail branches
	adr	x9, leaf_plain
	paciza	x9
	adr	x30, 1f
	mov	x0, #0
	braaz	x9
1:	cmp	x0, #42
	b.eq	1f
	FAIL	8
1:	adr	x9, leaf_plain
	pacizb	x9
	adr	x30, 1f
	mov	x0, #0
	brabz	x9
1:	cmp	x0, #42
	b.eq	1f
	FAIL	9
1:	adr	x9, leaf_plain
	mov	x10, #77
	pacia	x9, x10
	adr	x30, 1f
	mov	x0, #0
	braa	x9, x10
1:	cmp	x0, #42
	b.eq	1f
	FAIL	10
1:	adr	x9, leaf_plain
	mov	x10, #78
	pacib	x9, x10
	adr	x30, 1f
	mov	x0, #0
	brab	x9, x10
1:	cmp	x0, #42
	b.eq	1f
	FAIL	11
1:
	// 12: PACDZA + LDRAA with a positive offset
	adrp	x1, table
	add	x1, x1, :lo12:table
	pacdza	x1
	ldraa	x0, [x1, #16]
	ldr	x2, =0x3333333333333333
	cmp	x0, x2
	b.eq	1f
	FAIL	12
1:
	// 13: PACDZB + LDRAB with a small negative offset
	adrp	x1, table
	add	x1, x1, :lo12:table
	add	x1, x1, #24
	pacdzb	x1
	ldrab	x0, [x1, #-8]
	ldr	x2, =0x3333333333333333
	cmp	x0, x2
	b.eq	1f
	FAIL	13
1:
	// 14: LDRAA with writeback: value and updated base register
	adrp	x1, table
	add	x1, x1, :lo12:table
	mov	x3, x1
	pacdza	x1
	ldraa	x0, [x1, #8]!
	ldr	x2, =0x2222222222222222
	cmp	x0, x2
	b.eq	1f
	FAIL	14
1:	add	x3, x3, #8
	cmp	x1, x3
	b.eq	1f
	FAIL	15
1:
	// 16: LDRAB with a negative writeback offset
	adrp	x1, table
	add	x1, x1, :lo12:table
	add	x1, x1, #32
	mov	x3, x1
	pacdzb	x1
	ldrab	x0, [x1, #-16]!
	ldr	x2, =0x3333333333333333
	cmp	x0, x2
	b.eq	1f
	FAIL	16
1:	sub	x3, x3, #16
	cmp	x1, x3
	b.eq	1f
	FAIL	17
1:
	// 18: LDRAA through the stack pointer (the signed address is placed in SP)
	adrp	x1, table
	add	x1, x1, :lo12:table
	pacdza	x1
	mov	x4, sp
	mov	sp, x1
	ldraa	x0, [sp, #24]
	mov	sp, x4
	ldr	x2, =0x4444444444444444
	cmp	x0, x2
	b.eq	1f
	FAIL	18
1:
	// 19: sign and authenticate round trips with all four keys
	adrp	x1, table
	add	x1, x1, :lo12:table
	mov	x5, x1
	mov	x2, #0x55
	pacda	x1, x2
	autda	x1, x2
	pacdb	x1, x2
	autdb	x1, x2
	pacia	x1, x2
	autia	x1, x2
	pacib	x1, x2
	autib	x1, x2
	pacdza	x1
	autdza	x1
	pacdzb	x1
	autdzb	x1
	paciza	x1
	autiza	x1
	pacizb	x1
	autizb	x1
	cmp	x1, x5
	b.eq	1f
	FAIL	19
1:
	// 20, 21: strip
	mov	x1, x5
	mov	x2, #9
	pacia	x1, x2
	xpaci	x1
	cmp	x1, x5
	b.eq	1f
	FAIL	20
1:	mov	x1, x5
	pacdb	x1, x2
	xpacd	x1
	cmp	x1, x5
	b.eq	1f
	FAIL	21
1:
	// 22, 23: PACGA is deterministic and leaves the low 32 bits clear
	ldr	x1, =0x123456789abcdef0
	mov	x2, #0x99
	pacga	x3, x1, x2
	pacga	x4, x1, x2
	cmp	x3, x4
	b.eq	1f
	FAIL	22
1:	tst	x3, #0xffffffff
	b.eq	1f
	FAIL	23
1:	pacga	xzr, x1, x2		// result discarded; the stack pointer must survive
	mov	x6, sp
	pacga	x7, x1, sp
	mov	x8, sp
	cmp	x6, x8
	b.eq	1f
	FAIL	24
1:
	// 25: HINT-space forms on x17/x16 and XPACLRI
	adr	x17, leaf_plain
	mov	x16, #5
	pacia1716
	autia1716
	pacib1716
	autib1716
	mov	x0, #0
	blr	x17
	cmp	x0, #42
	b.eq	1f
	FAIL	25
1:	adr	x30, 1f
	paciaz
	autiaz
	pacibz
	autibz
	xpaclri
	ret
1:
	// done
#ifdef AS_FUNCTION
	mov	x0, #0
fail:
	ldp	x29, x30, [sp], #16
	ret
#else
	mov	x0, #1
	adr	x1, msg_ok
	mov	x2, #7
	mov	x8, #64
	svc	#0
	mov	x0, #0
	mov	x8, #93
	svc	#0

fail:
	mov	x8, #93
	svc	#0
#endif

	// Never executed: forms without a single-instruction equivalent.
never:
	ldraa	x0, [x1, #-512]
	ldrab	x0, [x1, #256]!
	ldraa	x0, [x1, #-4096]!
	ret

leaf_hint:
	paciasp
	mov	x0, #1
	autiasp
	ret

leaf_retab:
	pacibsp
	mov	x0, #2
	retab

leaf_retaa:
	paciasp
	mov	x0, #3
	retaa

leaf_plain:
	mov	x0, #42
	ret

	.ltorg

	.section .rodata
msg_ok:	.ascii	"ALL OK\n"
	.balign	8
table:	.quad	0x1111111111111111
	.quad	0x2222222222222222
	.quad	0x3333333333333333
	.quad	0x4444444444444444
	.quad	0x5555555555555555

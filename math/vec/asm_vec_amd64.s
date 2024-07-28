//go:build amd64 && !purego

#include "textflag.h"

TEXT ·addAssignUint32AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (BX)(SI*4), Y1

	VPADDD Y0, Y1, Y2

	VMOVDQU Y2, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (BX)(SI*4), R11

	ADDQ R10, R11

	MOVL R11, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·addAssignUint64AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (BX)(SI*8), Y1

	VPADDQ Y0, Y1, Y2

	VMOVDQU Y2, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (BX)(SI*8), R11

	ADDQ R10, R11

	MOVQ R11, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·subAssignUint32AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (BX)(SI*4), Y1

	VPSUBD Y1, Y0, Y2

	VMOVDQU Y2, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (BX)(SI*4), R11

	SUBQ R11, R10

	MOVL R10, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·subAssignUint64AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (BX)(SI*8), Y1

	VPSUBQ Y1, Y0, Y2

	VMOVDQU Y2, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (BX)(SI*8), R11

	SUBQ R11, R10

	MOVQ R10, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·scalarMulAssignUint32AVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VPBROADCASTD c+24(FP), Y2

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0

	VPMULLD Y0, Y2, Y1

	VMOVDQU Y1, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	MOVL c+24(FP), R12

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10

	IMULQ R12, R10

	MOVL R10, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·scalarMulAssignUint64AVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VPBROADCASTQ c+24(FP), Y2
	VPSHUFD      $0b10110001, Y2, Y3

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0

	VPMULLD Y0, Y3, Y4
	VPSRLQ  $32, Y4, Y5
	VPADDQ  Y5, Y4, Y5
	VPSLLQ  $32, Y5, Y5

	VPMULUDQ Y0, Y2, Y6
	VPADDD   Y5, Y6, Y7

	VMOVDQU Y7, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	MOVQ c+24(FP), R12

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10

	IMULQ R12, R10

	MOVQ R10, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·scalarMulAddAssignUint32AVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VPBROADCASTD c+24(FP), Y2

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (CX)(SI*4), Y1

	VPMULLD Y0, Y2, Y3
	VPADDD  Y3, Y1, Y1

	VMOVDQU Y1, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	MOVL c+24(FP), R12

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (CX)(SI*4), R11

	IMULQ R12, R10
	ADDL  R11, R10

	MOVL R10, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·scalarMulAddAssignUint64AVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VPBROADCASTQ c+24(FP), Y2
	VPSHUFD      $0b10110001, Y2, Y3

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (CX)(SI*8), Y1

	VPMULLD Y0, Y3, Y4
	VPSRLQ  $32, Y4, Y5
	VPADDQ  Y5, Y4, Y5
	VPSLLQ  $32, Y5, Y5

	VPMULUDQ Y0, Y2, Y6
	VPADDD   Y5, Y6, Y7

	VPADDQ Y1, Y7, Y7

	VMOVDQU Y7, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	MOVQ c+24(FP), R12

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (CX)(SI*8), R11

	IMULQ R12, R10
	ADDQ  R11, R10

	MOVQ R10, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·scalarMulSubAssignUint32AVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VPBROADCASTD c+24(FP), Y2

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (CX)(SI*4), Y1

	VPMULLD Y0, Y2, Y3
	VPSUBD  Y3, Y1, Y1

	VMOVDQU Y1, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	MOVL c+24(FP), R12

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (CX)(SI*4), R11

	IMULQ R12, R10
	SUBL  R10, R11

	MOVL R11, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·scalarMulSubAssignUint64AVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VPBROADCASTQ c+24(FP), Y2
	VPSHUFD      $0b10110001, Y2, Y3

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (CX)(SI*8), Y1

	VPMULLD Y0, Y3, Y4
	VPSRLQ  $32, Y4, Y5
	VPADDQ  Y5, Y4, Y5
	VPSLLQ  $32, Y5, Y5

	VPMULUDQ Y0, Y2, Y6
	VPADDD   Y5, Y6, Y7

	VPSUBQ Y7, Y1, Y7

	VMOVDQU Y7, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	MOVQ c+24(FP), R12

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (CX)(SI*8), R11

	IMULQ R12, R10
	SUBQ  R10, R11

	MOVQ R11, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·elementWiseMulAssignUint32AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (BX)(SI*4), Y1

	VPMULLD Y0, Y1, Y2

	VMOVDQU Y2, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (BX)(SI*4), R11

	IMULQ R11, R10

	MOVL R10, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·elementWiseMulAssignUint64AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	VPBROADCASTQ c+24(FP), Y2
	VPSHUFD      $0b10110001, Y2, Y3

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (BX)(SI*8), Y1
	VPSHUFD $0b10110001, Y1, Y2

	VPMULLD Y0, Y2, Y4
	VPSRLQ  $32, Y4, Y5
	VPADDQ  Y5, Y4, Y5
	VPSLLQ  $32, Y5, Y5

	VPMULUDQ Y0, Y1, Y6
	VPADDD   Y5, Y6, Y7

	VMOVDQU Y7, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (BX)(SI*8), R11

	IMULQ R11, R10

	MOVQ R10, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·elementWiseMulAddAssignUint32AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (BX)(SI*4), Y1
	VMOVDQU (CX)(SI*4), Y2

	VPMULLD Y0, Y1, Y3
	VPADDD  Y3, Y2, Y2

	VMOVDQU Y2, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (BX)(SI*4), R11
	MOVL (CX)(SI*4), R12

	IMULQ R11, R10
	ADDL  R12, R10

	MOVL R10, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·elementWiseMulAddAssignUint64AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (BX)(SI*8), Y1
	VMOVDQU (CX)(SI*8), Y2
	VPSHUFD $0b10110001, Y1, Y3

	VPMULLD Y0, Y3, Y4
	VPSRLQ  $32, Y4, Y5
	VPADDQ  Y5, Y4, Y5
	VPSLLQ  $32, Y5, Y5

	VPMULUDQ Y0, Y1, Y6
	VPADDD   Y5, Y6, Y7

	VPADDQ Y2, Y7, Y7

	VMOVDQU Y7, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (BX)(SI*8), R11
	MOVQ (CX)(SI*8), R12

	IMULQ R11, R10
	ADDQ  R12, R10

	MOVQ R10, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·elementWiseMulSubAssignUint32AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $8, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (BX)(SI*4), Y1
	VMOVDQU (CX)(SI*4), Y2

	VPMULLD Y0, Y1, Y3
	VPSUBD  Y3, Y2, Y2

	VMOVDQU Y2, (CX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVL (AX)(SI*4), R10
	MOVL (BX)(SI*4), R11
	MOVL (CX)(SI*4), R12

	IMULQ R11, R10
	SUBL  R10, R12

	MOVL R12, (CX)(SI*4)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

TEXT ·elementWiseMulSubAssignUint64AVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	XORQ DI, DI
	ADDQ $4, DI

	JMP loop_end

loop_body:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (BX)(SI*8), Y1
	VMOVDQU (CX)(SI*8), Y2
	VPSHUFD $0b10110001, Y1, Y3

	VPMULLD Y0, Y3, Y4
	VPSRLQ  $32, Y4, Y5
	VPADDQ  Y5, Y4, Y5
	VPSLLQ  $32, Y5, Y5

	VPMULUDQ Y0, Y1, Y6
	VPADDD   Y5, Y6, Y7

	VPSUBQ Y7, Y2, Y7

	VMOVDQU Y7, (CX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

loop_end:
	CMPQ DI, DX
	JL   loop_body

	JMP leftover_loop_end

leftover_loop_body:
	MOVQ (AX)(SI*8), R10
	MOVQ (BX)(SI*8), R11
	MOVQ (CX)(SI*8), R12

	IMULQ R11, R10
	SUBQ  R10, R12

	MOVQ R12, (CX)(SI*8)

	ADDQ $1, SI

leftover_loop_end:
	CMPQ SI, DX
	JL   leftover_loop_body

	RET

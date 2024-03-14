//go:build amd64 && !purego

#include "textflag.h"

TEXT ·monomialSubOneMulAssignUint32AVX2(SB), NOSPLIT, $0-56
	MOVQ p0_base+0(FP), AX
	MOVQ pOut_base+32(FP), BX

	MOVQ d+24(FP), DX
	MOVQ pOut_len+40(FP), CX

	VPXOR Y5, Y5, Y5 // (0, 0, 0, 0)

	CMPQ DX, CX
	JGE  case_1

case_0:
	// for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	SUBQ DX, DI

	JMP case_0_loop_0_end

case_0_loop_0:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y5, Y2
	VPSUBD Y1, Y2, Y2

	VMOVDQU Y2, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_0_loop_0_end:
	MOVQ DI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_0_loop_0

	JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	XORL R13, R13
	SUBL R10, R13
	SUBL R11, R13

	MOVL R13, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_0_loop_0_leftover

	// for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	XORQ DI, DI

	JMP case_0_loop_1_end

case_0_loop_1:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y1, Y2

	VMOVDQU Y2, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_0_loop_1_end:
	MOVQ SI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_0_loop_1

	JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	SUBL R10, R11

	MOVL R11, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_0_loop_1_leftover

	RET

case_1:
	// for i, ii := 0, 2*polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	ADDQ CX, DI
	SUBQ DX, DI

	JMP case_1_loop_0_end

case_1_loop_0:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y1, Y2

	VMOVDQU Y2, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_1_loop_0_end:
	MOVQ DI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_1_loop_0

	JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	SUBL R10, R11

	MOVL R11, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_1_loop_0_leftover

	// for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	SUBQ CX, SI
	XORQ DI, DI

	JMP case_1_loop_1_end

case_1_loop_1:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y5, Y2
	VPSUBD Y1, Y2, Y2

	VMOVDQU Y2, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_1_loop_1_end:
	MOVQ SI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_1_loop_1

	JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	XORL R13, R13
	SUBL R10, R13
	SUBL R11, R13

	MOVL R13, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_1_loop_1_leftover

	RET

TEXT ·monomialSubOneMulAssignUint64AVX2(SB), NOSPLIT, $0-56
	MOVQ p0_base+0(FP), AX
	MOVQ pOut_base+32(FP), BX

	MOVQ d+24(FP), DX
	MOVQ pOut_len+40(FP), CX

	VPXOR Y5, Y5, Y5 // (0, 0, 0, 0)

	CMPQ DX, CX
	JGE  case_1

case_0:
	// for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	SUBQ DX, DI

	JMP case_0_loop_0_end

case_0_loop_0:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y5, Y2
	VPSUBQ Y1, Y2, Y2

	VMOVDQU Y2, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_0_loop_0_end:
	MOVQ DI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_0_loop_0

	JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	XORQ R13, R13
	SUBQ R10, R13
	SUBQ R11, R13

	MOVQ R13, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_0_loop_0_leftover

	// for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	XORQ DI, DI

	JMP case_0_loop_1_end

case_0_loop_1:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y1, Y2

	VMOVDQU Y2, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_0_loop_1_end:
	MOVQ SI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_0_loop_1

	JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	SUBQ R10, R11

	MOVQ R11, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_0_loop_1_leftover

	RET

case_1:
	// for i, ii := 0, 2*polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	ADDQ CX, DI
	SUBQ DX, DI

	JMP case_1_loop_0_end

case_1_loop_0:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y1, Y2

	VMOVDQU Y2, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_1_loop_0_end:
	MOVQ DI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_1_loop_0

	JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	SUBQ R10, R11

	MOVQ R11, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_1_loop_0_leftover

	// for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	SUBQ CX, SI
	XORQ DI, DI

	JMP case_1_loop_1_end

case_1_loop_1:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y5, Y2
	VPSUBQ Y1, Y2, Y2

	VMOVDQU Y2, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_1_loop_1_end:
	MOVQ SI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_1_loop_1

	JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	XORQ R13, R13
	SUBQ R10, R13
	SUBQ R11, R13

	MOVQ R13, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_1_loop_1_leftover

	RET

TEXT ·monomialSubOneMulAddAssignUint32AVX2(SB), NOSPLIT, $0-56
	MOVQ p0_base+0(FP), AX
	MOVQ pOut_base+32(FP), BX

	MOVQ d+24(FP), DX
	MOVQ pOut_len+40(FP), CX

	VPXOR Y5, Y5, Y5 // (0, 0, 0, 0)

	CMPQ DX, CX
	JGE  case_1

case_0:
	// for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	SUBQ DX, DI

	JMP case_0_loop_0_end

case_0_loop_0:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y5, Y2
	VPSUBD Y1, Y2, Y2

	VMOVDQU (BX)(SI*4), Y3
	VPADDD  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_0_loop_0_end:
	MOVQ DI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_0_loop_0

	JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	XORL R13, R13
	SUBL R10, R13
	SUBL R11, R13

	MOVL (BX)(SI*4), R14
	ADDL R13, R14
	MOVL R14, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_0_loop_0_leftover

	// for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	XORQ DI, DI

	JMP case_0_loop_1_end

case_0_loop_1:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y1, Y2

	VMOVDQU (BX)(SI*4), Y3
	VPADDD  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_0_loop_1_end:
	MOVQ SI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_0_loop_1

	JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	SUBL R10, R11

	MOVL (BX)(SI*4), R12
	ADDL R11, R12
	MOVL R12, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_0_loop_1_leftover

	RET

case_1:
	// for i, ii := 0, 2*polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	ADDQ CX, DI
	SUBQ DX, DI

	JMP case_1_loop_0_end

case_1_loop_0:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y1, Y2

	VMOVDQU (BX)(SI*4), Y3
	VPADDD  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_1_loop_0_end:
	MOVQ DI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_1_loop_0

	JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	SUBL R10, R11

	MOVL (BX)(SI*4), R12
	ADDL R11, R12
	MOVL R12, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_1_loop_0_leftover

	// for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	SUBQ CX, SI
	XORQ DI, DI

	JMP case_1_loop_1_end

case_1_loop_1:
	VMOVDQU (AX)(SI*4), Y0
	VMOVDQU (AX)(DI*4), Y1

	VPSUBD Y0, Y5, Y2
	VPSUBD Y1, Y2, Y2

	VMOVDQU (BX)(SI*4), Y3
	VPADDD  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*4)

	ADDQ $8, SI
	ADDQ $8, DI

case_1_loop_1_end:
	MOVQ SI, R10
	ADDQ $8, R10
	CMPQ R10, CX
	JLE  case_1_loop_1

	JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
	MOVL (AX)(SI*4), R10
	MOVL (AX)(DI*4), R11

	XORL R13, R13
	SUBL R10, R13
	SUBL R11, R13

	MOVL (BX)(SI*4), R14
	ADDL R13, R14
	MOVL R14, (BX)(SI*4)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_1_loop_1_leftover

	RET

TEXT ·monomialSubOneMulAddAssignUint64AVX2(SB), NOSPLIT, $0-56
	MOVQ p0_base+0(FP), AX
	MOVQ pOut_base+32(FP), BX

	MOVQ d+24(FP), DX
	MOVQ pOut_len+40(FP), CX

	VPXOR Y5, Y5, Y5 // (0, 0, 0, 0)

	CMPQ DX, CX
	JGE  case_1

case_0:
	// for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	SUBQ DX, DI

	JMP case_0_loop_0_end

case_0_loop_0:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y5, Y2
	VPSUBQ Y1, Y2, Y2

	VMOVDQU (BX)(SI*8), Y3
	VPADDQ  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_0_loop_0_end:
	MOVQ DI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_0_loop_0

	JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	XORQ R13, R13
	SUBQ R10, R13
	SUBQ R11, R13

	MOVQ (BX)(SI*8), R14
	ADDQ R13, R14
	MOVQ R14, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_0_loop_0_leftover

	// for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	XORQ DI, DI

	JMP case_0_loop_1_end

case_0_loop_1:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y1, Y2

	VMOVDQU (BX)(SI*8), Y3
	VPADDQ  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_0_loop_1_end:
	MOVQ SI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_0_loop_1

	JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	SUBQ R10, R11

	MOVQ (BX)(SI*8), R12
	ADDQ R11, R12
	MOVQ R12, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_0_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_0_loop_1_leftover

	RET

case_1:
	// for i, ii := 0, 2*polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1
	XORQ SI, SI
	MOVQ CX, DI
	ADDQ CX, DI
	SUBQ DX, DI

	JMP case_1_loop_0_end

case_1_loop_0:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y1, Y2

	VMOVDQU (BX)(SI*8), Y3
	VPADDQ  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_1_loop_0_end:
	MOVQ DI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_1_loop_0

	JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	SUBQ R10, R11

	MOVQ (BX)(SI*8), R12
	ADDQ R11, R12
	MOVQ R12, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_0_leftover_end:
	CMPQ DI, CX
	JL   case_1_loop_0_leftover

	// for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1
	MOVQ DX, SI
	SUBQ CX, SI
	XORQ DI, DI

	JMP case_1_loop_1_end

case_1_loop_1:
	VMOVDQU (AX)(SI*8), Y0
	VMOVDQU (AX)(DI*8), Y1

	VPSUBQ Y0, Y5, Y2
	VPSUBQ Y1, Y2, Y2

	VMOVDQU (BX)(SI*8), Y3
	VPADDQ  Y2, Y3, Y3
	VMOVDQU Y3, (BX)(SI*8)

	ADDQ $4, SI
	ADDQ $4, DI

case_1_loop_1_end:
	MOVQ SI, R10
	ADDQ $4, R10
	CMPQ R10, CX
	JLE  case_1_loop_1

	JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
	MOVQ (AX)(SI*8), R10
	MOVQ (AX)(DI*8), R11

	XORQ R13, R13
	SUBQ R10, R13
	SUBQ R11, R13

	MOVQ (BX)(SI*8), R14
	ADDQ R13, R14
	MOVQ R14, (BX)(SI*8)

	ADDQ $1, SI
	ADDQ $1, DI

case_1_loop_1_leftover_end:
	CMPQ SI, CX
	JL   case_1_loop_1_leftover

	RET

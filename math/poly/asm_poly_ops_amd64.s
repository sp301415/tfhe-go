//go:build amd64 && !purego

#include "textflag.h"

TEXT ·monomialSubOneMulAssignUint32AVX2(SB), NOSPLIT, $0-56
    MOVQ v0+0(FP), AX
    MOVQ vOut+32(FP), BX

    MOVQ d+24(FP), R10
    MOVQ vOut_len+40(FP), R11

    CMPQ R10, $0
    JLE case_1

case_0:

// for j, jj := 0, polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    MOVQ R11, DI
    SUBQ R10, DI

    JMP case_0_loop_0_end

case_0_loop_0:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1

    VPADDD Y0, Y1, Y1
    VPXOR Y2, Y2, Y2
    VPSUBD Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_0_loop_0_end:
    MOVQ DI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_0_loop_0

    JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13

    ADDL R12, R13
    XORL R14, R14
    SUBL R13, R14

    MOVL R14, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_0_loop_0_leftover

// for j, jj := d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R10, SI
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
    MOVQ SI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_0_loop_1

    JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13

    SUBL R12, R13

    MOVL R13, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_0_loop_1_leftover

    RET

case_1:

// for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    XORQ DI, DI
    SUBQ R10, DI

    JMP case_1_loop_0_end

case_1_loop_0:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1

    VPSUBD Y0, Y1, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_1_loop_0_end:
    MOVQ DI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_1_loop_0

    JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13

    SUBL R12, R13

    MOVL R13, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_1_loop_0_leftover

// for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R11, SI
    ADDQ R10, SI
    XORQ DI, DI

    JMP case_1_loop_1_end

case_1_loop_1:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1

    VPADDD Y0, Y1, Y1
    VPXOR Y2, Y2, Y2
    VPSUBD Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_1_loop_1_end:
    MOVQ SI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_1_loop_1

    JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13

    ADDL R12, R13
    XORL R14, R14
    SUBL R13, R14

    MOVL R14, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_1_loop_1_leftover

    RET

TEXT ·monomialSubOneMulAssignUint64AVX2(SB), NOSPLIT, $0-56
    MOVQ v0+0(FP), AX
    MOVQ vOut+32(FP), BX

    MOVQ d+24(FP), R10
    MOVQ vOut_len+40(FP), R11

    CMPQ R10, $0
    JLE case_1

case_0:

// for j, jj := 0, polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    MOVQ R11, DI
    SUBQ R10, DI

    JMP case_0_loop_0_end

case_0_loop_0:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1

    VPADDQ Y0, Y1, Y1
    VPXOR Y2, Y2, Y2
    VPSUBQ Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_0_loop_0_end:
    MOVQ DI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_0_loop_0

    JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13

    ADDQ R12, R13
    XORQ R14, R14
    SUBQ R13, R14

    MOVQ R14, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_0_loop_0_leftover

// for j, jj := d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R10, SI
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
    MOVQ SI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_0_loop_1

    JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13

    SUBQ R12, R13

    MOVQ R13, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_0_loop_1_leftover

    RET

case_1:

// for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    XORQ DI, DI
    SUBQ R10, DI

    JMP case_1_loop_0_end

case_1_loop_0:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1

    VPSUBQ Y0, Y1, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_1_loop_0_end:
    MOVQ DI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_1_loop_0

    JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13

    SUBQ R12, R13

    MOVQ R13, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_1_loop_0_leftover

// for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R11, SI
    ADDQ R10, SI
    XORQ DI, DI

    JMP case_1_loop_1_end

case_1_loop_1:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1

    VPADDQ Y0, Y1, Y1
    VPXOR Y2, Y2, Y2
    VPSUBQ Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_1_loop_1_end:
    MOVQ SI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_1_loop_1

    JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13

    ADDQ R12, R13
    XORQ R14, R14
    SUBQ R13, R14

    MOVQ R14, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_1_loop_1_leftover

    RET

TEXT ·monomialSubOneMulAddAssignUint32AVX2(SB), NOSPLIT, $0-56
    MOVQ v0+0(FP), AX
    MOVQ vOut+32(FP), BX

    MOVQ d+24(FP), R10
    MOVQ vOut_len+40(FP), R11

    CMPQ R10, $0
    JLE case_1

case_0:

// for j, jj := 0, polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    MOVQ R11, DI
    SUBQ R10, DI

    JMP case_0_loop_0_end

case_0_loop_0:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1
    VMOVDQU (BX)(SI*4), Y2

    VPADDD Y0, Y1, Y1
    VPSUBD Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_0_loop_0_end:
    MOVQ DI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_0_loop_0

    JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13
    MOVL (BX)(SI*4), R14

    ADDL R12, R13
    SUBL R13, R14

    MOVL R14, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_0_loop_0_leftover

// for j, jj := d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R10, SI
    XORQ DI, DI

    JMP case_0_loop_1_end

case_0_loop_1:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1
    VMOVDQU (BX)(SI*4), Y2

    VPSUBD Y0, Y1, Y1
    VPADDD Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_0_loop_1_end:
    MOVQ SI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_0_loop_1

    JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13
    MOVL (BX)(SI*4), R14

    SUBL R12, R13
    ADDL R13, R14

    MOVL R14, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_0_loop_1_leftover

    RET

case_1:

// for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    XORQ DI, DI
    SUBQ R10, DI

    JMP case_1_loop_0_end

case_1_loop_0:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1
    VMOVDQU (BX)(SI*4), Y2

    VPSUBD Y0, Y1, Y1
    VPADDD Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_1_loop_0_end:
    MOVQ DI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_1_loop_0

    JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13
    MOVL (BX)(SI*4), R14

    SUBL R12, R13
    ADDL R13, R14

    MOVL R14, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_1_loop_0_leftover

// for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R11, SI
    ADDQ R10, SI
    XORQ DI, DI

    JMP case_1_loop_1_end

case_1_loop_1:
    VMOVDQU (AX)(SI*4), Y0
    VMOVDQU (AX)(DI*4), Y1
    VMOVDQU (BX)(SI*4), Y2

    VPADDD Y0, Y1, Y1
    VPSUBD Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*4)

    ADDQ $8, SI
    ADDQ $8, DI

case_1_loop_1_end:
    MOVQ SI, R12
    ADDQ $8, R12
    CMPQ R12, R11
    JLE case_1_loop_1

    JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
    MOVL (AX)(SI*4), R12
    MOVL (AX)(DI*4), R13
    MOVL (BX)(SI*4), R14

    ADDL R12, R13
    SUBL R13, R14

    MOVL R14, (BX)(SI*4)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_1_loop_1_leftover

    RET

TEXT ·monomialSubOneMulAddAssignUint64AVX2(SB), NOSPLIT, $0-56
    MOVQ v0+0(FP), AX
    MOVQ vOut+32(FP), BX

    MOVQ d+24(FP), R10
    MOVQ vOut_len+40(FP), R11

    CMPQ R10, $0
    JLE case_1

case_0:

// for j, jj := 0, polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    MOVQ R11, DI
    SUBQ R10, DI

    JMP case_0_loop_0_end

case_0_loop_0:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1
    VMOVDQU (BX)(SI*8), Y2

    VPADDQ Y0, Y1, Y1
    VPSUBQ Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_0_loop_0_end:
    MOVQ DI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_0_loop_0

    JMP case_0_loop_0_leftover_end

case_0_loop_0_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13
    MOVQ (BX)(SI*8), R14

    ADDQ R12, R13
    SUBQ R13, R14

    MOVQ R14, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_0_loop_0_leftover

// for j, jj := d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R10, SI
    XORQ DI, DI

    JMP case_0_loop_1_end

case_0_loop_1:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1
    VMOVDQU (BX)(SI*8), Y2

    VPSUBQ Y0, Y1, Y1
    VPADDQ Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_0_loop_1_end:
    MOVQ SI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_0_loop_1

    JMP case_0_loop_1_leftover_end

case_0_loop_1_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13
    MOVQ (BX)(SI*8), R14

    SUBQ R12, R13
    ADDQ R13, R14

    MOVQ R14, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_0_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_0_loop_1_leftover

    RET

case_1:

// for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1
    XORQ SI, SI
    XORQ DI, DI
    SUBQ R10, DI

    JMP case_1_loop_0_end

case_1_loop_0:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1
    VMOVDQU (BX)(SI*8), Y2

    VPSUBQ Y0, Y1, Y1
    VPADDQ Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_1_loop_0_end:
    MOVQ DI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_1_loop_0

    JMP case_1_loop_0_leftover_end

case_1_loop_0_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13
    MOVQ (BX)(SI*8), R14

    SUBQ R12, R13
    ADDQ R13, R14

    MOVQ R14, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_0_leftover_end:
    CMPQ DI, R11
    JL case_1_loop_0_leftover

// for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1
    MOVQ R11, SI
    ADDQ R10, SI
    XORQ DI, DI

    JMP case_1_loop_1_end

case_1_loop_1:
    VMOVDQU (AX)(SI*8), Y0
    VMOVDQU (AX)(DI*8), Y1
    VMOVDQU (BX)(SI*8), Y2

    VPADDQ Y0, Y1, Y1
    VPSUBQ Y1, Y2, Y2

    VMOVDQU Y2, (BX)(SI*8)

    ADDQ $4, SI
    ADDQ $4, DI

case_1_loop_1_end:
    MOVQ SI, R12
    ADDQ $4, R12
    CMPQ R12, R11
    JLE case_1_loop_1

    JMP case_1_loop_1_leftover_end

case_1_loop_1_leftover:
    MOVQ (AX)(SI*8), R12
    MOVQ (AX)(DI*8), R13
    MOVQ (BX)(SI*8), R14

    ADDQ R12, R13
    SUBQ R13, R14

    MOVQ R14, (BX)(SI*8)

    ADDQ $1, SI
    ADDQ $1, DI

case_1_loop_1_leftover_end:
    CMPQ SI, R11
    JL case_1_loop_1_leftover

    RET

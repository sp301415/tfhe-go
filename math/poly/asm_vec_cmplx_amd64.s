//go:build amd64 && !purego

#include "textflag.h"

TEXT ·addCmplxAssignAVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VADDPD Y1, Y0, Y2

	VMOVUPD Y2, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·subCmplxAssignAVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VSUBPD Y1, Y0, Y2

	VMOVUPD Y2, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·negCmplxAssignAVX2(SB), NOSPLIT, $0-48
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+24(FP), CX

	MOVQ vOut_len+32(FP), DX

	VPXOR Y1, Y1, Y1
	XORQ  SI, SI
	JMP   loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0

	VSUBPD Y0, Y1, Y2

	VMOVUPD Y2, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·floatMulCmplxAssignAVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VBROADCASTSD c+24(FP), Y1

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0

	VMULPD Y0, Y1, Y0

	VMOVUPD Y0, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·floatMulAddCmplxAssignAVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VBROADCASTSD c+24(FP), Y1

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (CX)(SI*8), Y2

	VFMADD231PD Y0, Y1, Y2

	VMOVUPD Y2, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·floatMulSubCmplxAssignAVX2(SB), NOSPLIT, $0-56
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+32(FP), CX

	MOVQ vOut_len+40(FP), DX

	VBROADCASTSD c+24(FP), Y1

	VPXOR Y10, Y10, Y10

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (CX)(SI*8), Y2

	VFMSUB231PD Y0, Y1, Y2
	VSUBPD      Y2, Y10, Y2

	VMOVUPD Y2, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·cmplxMulCmplxAssignAVX2(SB), NOSPLIT, $0-64
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+40(FP), CX

	MOVQ vOut_len+48(FP), DX

	VBROADCASTSD c_real+24(FP), Y2
	VBROADCASTSD c_imag+32(FP), Y3

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD 32(AX)(SI*8), Y1

	VMULPD      Y1, Y3, Y4
	VFMSUB231PD Y0, Y2, Y4

	VMULPD      Y0, Y3, Y5
	VFMADD231PD Y1, Y2, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·cmplxMulAddCmplxAssignAVX2(SB), NOSPLIT, $0-64
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+40(FP), CX

	MOVQ vOut_len+48(FP), DX

	VBROADCASTSD c_real+24(FP), Y2
	VBROADCASTSD c_imag+32(FP), Y3

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD 32(AX)(SI*8), Y1
	VMOVUPD (CX)(SI*8), Y4
	VMOVUPD 32(CX)(SI*8), Y5

	VFMSUB231PD Y1, Y3, Y4
	VFMSUB231PD Y0, Y2, Y4

	VFMADD231PD Y0, Y3, Y5
	VFMADD231PD Y1, Y2, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·cmplxMulSubCmplxAssignAVX2(SB), NOSPLIT, $0-64
	MOVQ v0_base+0(FP), AX
	MOVQ vOut_base+40(FP), CX

	MOVQ vOut_len+48(FP), DX

	VBROADCASTSD c_real+24(FP), Y2
	VBROADCASTSD c_imag+32(FP), Y3

	VPXOR Y10, Y10, Y10

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD 32(AX)(SI*8), Y1
	VMOVUPD (CX)(SI*8), Y4
	VMOVUPD 32(CX)(SI*8), Y5

	VFMSUB231PD Y0, Y2, Y4
	VFMSUB231PD Y1, Y3, Y4

	VFMSUB231PD Y0, Y3, Y5
	VFMADD231PD Y1, Y2, Y5
	VSUBPD      Y5, Y10, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·elementWiseMulCmplxAssignAVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD 32(AX)(SI*8), Y1
	VMOVUPD (BX)(SI*8), Y2
	VMOVUPD 32(BX)(SI*8), Y3

	VMULPD      Y1, Y3, Y4
	VFMSUB231PD Y0, Y2, Y4

	VMULPD      Y0, Y3, Y5
	VFMADD231PD Y1, Y2, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·elementWiseMulAddCmplxAssignAVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD 32(AX)(SI*8), Y1
	VMOVUPD (BX)(SI*8), Y2
	VMOVUPD 32(BX)(SI*8), Y3
	VMOVUPD (CX)(SI*8), Y4
	VMOVUPD 32(CX)(SI*8), Y5

	VFMSUB231PD Y1, Y3, Y4
	VFMSUB231PD Y0, Y2, Y4

	VFMADD231PD Y0, Y3, Y5
	VFMADD231PD Y1, Y2, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·elementWiseMulSubCmplxAssignAVX2(SB), NOSPLIT, $0-72
	MOVQ v0_base+0(FP), AX
	MOVQ v1_base+24(FP), BX
	MOVQ vOut_base+48(FP), CX

	MOVQ vOut_len+56(FP), DX

	VPXOR Y10, Y10, Y10

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD 32(AX)(SI*8), Y1
	VMOVUPD (BX)(SI*8), Y2
	VMOVUPD 32(BX)(SI*8), Y3
	VMOVUPD (CX)(SI*8), Y4
	VMOVUPD 32(CX)(SI*8), Y5

	VFMSUB231PD Y0, Y2, Y4
	VFMSUB231PD Y1, Y3, Y4

	VFMSUB231PD Y0, Y3, Y5
	VFMADD231PD Y1, Y2, Y5
	VSUBPD      Y5, Y10, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

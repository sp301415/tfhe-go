//go:build amd64 && !purego

#include "textflag.h"

TEXT ·roundCmplxAssignAVX2(SB), $0-48
	MOVQ v0+0(FP), AX
	MOVQ vOut+24(FP), CX

	MOVQ vOut_len+32(FP), DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0

	VROUNDPD $0, Y0, Y0

	VMOVUPD Y0, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·addCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

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

TEXT ·subCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

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

TEXT ·negCmplxAssignAVX2(SB), $0-48
	MOVQ v0+0(FP), AX
	MOVQ vOut+24(FP), CX

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

TEXT ·floatMulCmplxAssignAVX2(SB), $0-56
	MOVQ v0+0(FP), AX
	MOVQ vOut+32(FP), CX

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

TEXT ·elementWiseMulCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

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

TEXT ·elementWiseMulAddCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

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

	VMOVUPD (CX)(SI*8), Y6
	VMOVUPD 32(CX)(SI*8), Y7

	VADDPD Y4, Y6, Y4
	VADDPD Y5, Y7, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·elementWiseMulSubCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

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

	VMOVUPD (CX)(SI*8), Y6
	VMOVUPD 32(CX)(SI*8), Y7

	VSUBPD Y4, Y6, Y4
	VSUBPD Y5, Y7, Y5

	VMOVUPD Y4, (CX)(SI*8)
	VMOVUPD Y5, 32(CX)(SI*8)

	ADDQ $8, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

//go:build amd64 && !purego

#include "textflag.h"

TEXT ·addCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

	MOVQ vOut_len+56(FP), DX
	ADDQ DX, DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VADDPD Y0, Y1, Y2

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
	ADDQ DX, DX

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
	ADDQ DX, DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0

	VXORPD Y1, Y1, Y1
	VSUBPD Y0, Y1, Y2

	VMOVUPD Y2, (CX)(SI*8)

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
	ADDQ DX, DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VSHUFPD $0b0101, Y1, Y1, Y2
	VSHUFPD $0b1111, Y0, Y0, Y3
	VSHUFPD $0b0000, Y0, Y0, Y4

	VMULPD         Y2, Y3, Y5
	VFMADDSUB231PD Y1, Y4, Y5

	VMOVUPD Y5, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·elementWiseMulAddCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

	MOVQ vOut_len+56(FP), DX
	ADDQ DX, DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VSHUFPD $0b0101, Y1, Y1, Y2
	VSHUFPD $0b1111, Y0, Y0, Y3
	VSHUFPD $0b0000, Y0, Y0, Y4

	VMULPD         Y2, Y3, Y5
	VFMADDSUB231PD Y1, Y4, Y5

	VMOVUPD (CX)(SI*8), Y6
	VADDPD  Y5, Y6, Y6
	VMOVUPD Y6, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

TEXT ·elementWiseMulSubCmplxAssignAVX2(SB), $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

	MOVQ vOut_len+56(FP), DX
	ADDQ DX, DX

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VSHUFPD $0b0101, Y1, Y1, Y2
	VSHUFPD $0b1111, Y0, Y0, Y3
	VSHUFPD $0b0000, Y0, Y0, Y4

	VMULPD         Y2, Y3, Y5
	VFMADDSUB231PD Y1, Y4, Y5

	VMOVUPD (CX)(SI*8), Y6
	VSUBPD  Y5, Y6, Y6
	VMOVUPD Y6, (CX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

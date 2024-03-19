//go:build amd64 && !purego

#include "textflag.h"

DATA ONE<>+0(SB)/8, $0x1 // 1
GLOBL ONE<>(SB), NOPTR | RODATA, $8

TEXT ·decomposePolyAssignUint32AVX2(SB), NOSPLIT, $0-64
	MOVQ p+0(FP), AX
	MOVQ decomposedOut+40(FP), BX

	MOVQ p_len+8(FP), CX              // N
	MOVQ decomposedOut_len+48(FP), DX // level

	// VET: go vet complains about VBROADCASTD on uint32 values.
	// See https://github.com/golang/go/issues/47625.
	VPBROADCASTD base+24(FP), Y10              // base
	VPBROADCASTD baseLog+28(FP), Y11           // baseLog
	VPBROADCASTD lastScaledBaseLog+32(FP), Y12 // lastScaledBaseLog

	// Create (1, 1, 1, ..., 1)
	VPBROADCASTD ONE<>+0(SB), Y0 // ONE

	VPSUBD Y0, Y10, Y13 // baseMask = base - 1
	VPSRLD $1, Y10, Y14 // baseHalf = base / 2
	VPSUBD Y0, Y11, Y15 // baseLog - 1
	VPSUBD Y0, Y12, Y9  // lastScaledBaseLog - 1

	XORQ SI, SI
	JMP  N_loop_end

N_loop:
	// x := p[i]
	VMOVDQU (AX)(SI*4), Y1

	// c := (x >> lsbl) + ((x >> (lsbl - 1)) & 1)
	// x >> (lsbl - 1)
	VPSRLVD Y9, Y1, Y3

	// c := x >> lsbl
	VPSRLD $1, Y3, Y2

	// (x >> (lsbl - 1) & 1)
	VANDPD Y3, Y0, Y3

	// c := (x >> lsbl) + (x >> (lsbl - 1) & 1)
	VPADDD Y2, Y3, Y1

	MOVQ DX, DI
	DECQ DI

	MOVQ DI, R10
	ADDQ DI, R10
	ADDQ DI, R10        // R10 = DI * 3
	JMP  level_loop_end

level_loop:
	// d[j].Coeffs[i] = c & baseMask
	VANDPD Y1, Y13, Y2 // d[j].Coeffs[i]

	// c >>= baseLog
	VPSRLVD Y11, Y1, Y1

	// c += d[j].Coeffs[i] >> (baseLog - 1)
	VPSRLVD Y15, Y2, Y3
	VPADDD  Y3, Y1, Y1

	// d[j].Coeffs[i] -= (d[j].Coeffs[i] & baseHalf) << 1
	VANDPD Y2, Y14, Y3
	VPSLLD $1, Y3, Y3
	VPSUBD Y3, Y2, Y2

	MOVQ    (BX)(R10*8), R11
	VMOVDQU Y2, (R11)(SI*4)

	DECQ DI
	SUBQ $3, R10

level_loop_end:
	CMPQ DI, $0
	JGE  level_loop

	ADDQ $8, SI

N_loop_end:
	CMPQ SI, CX
	JL   N_loop

	RET

TEXT ·decomposePolyAssignUint64AVX2(SB), NOSPLIT, $0-72
	MOVQ p+0(FP), AX
	MOVQ decomposedOut+48(FP), BX

	MOVQ p_len+8(FP), CX              // N
	MOVQ decomposedOut_len+56(FP), DX // level

	VPBROADCASTQ base+24(FP), Y10              // base
	VPBROADCASTQ baseLog+32(FP), Y11           // baseLog
	VPBROADCASTQ lastScaledBaseLog+40(FP), Y12 // lastScaledBaseLog

	// Create (1, 1, 1, ..., 1)
	VPBROADCASTQ ONE<>+0(SB), Y0 // ONE

	VPSUBQ Y0, Y10, Y13 // baseMask = base - 1
	VPSRLQ $1, Y10, Y14 // baseHalf = base / 2
	VPSUBQ Y0, Y11, Y15 // baseLog - 1
	VPSUBQ Y0, Y12, Y9  // lastScaledBaseLog - 1

	XORQ SI, SI
	JMP  N_loop_end

N_loop:
	// x := p[i]
	VMOVDQU (AX)(SI*8), Y1

	// c := (x >> lsbl) + ((x >> (lsbl - 1)) & 1)
	// x >> (lsbl - 1)
	VPSRLVQ Y9, Y1, Y3

	// c := x >> lsbl
	VPSRLQ $1, Y3, Y2

	// (x >> (lsbl - 1) & 1)
	VANDPD Y3, Y0, Y3

	// c := (x >> lsbl) + (x >> (lsbl - 1) & 1)
	VPADDQ Y2, Y3, Y1

	MOVQ DX, DI
	DECQ DI

	MOVQ DI, R10
	ADDQ DI, R10
	ADDQ DI, R10        // R10 = DI * 3
	JMP  level_loop_end

level_loop:
	// d[j].Coeffs[i] = c & baseMask
	VANDPD Y1, Y13, Y2 // d[j].Coeffs[i]

	// c >>= baseLog
	VPSRLVQ Y11, Y1, Y1

	// c += d[j].Coeffs[i] >> (baseLog - 1)
	VPSRLVQ Y15, Y2, Y3
	VPADDQ  Y3, Y1, Y1

	// d[j].Coeffs[i] -= (d[j].Coeffs[i] & baseHalf) << 1
	VANDPD Y2, Y14, Y3
	VPSLLQ $1, Y3, Y3
	VPSUBQ Y3, Y2, Y2

	MOVQ    (BX)(R10*8), R11
	VMOVDQU Y2, (R11)(SI*8)

	DECQ DI
	SUBQ $3, R10

level_loop_end:
	CMPQ DI, $0
	JGE  level_loop

	ADDQ $4, SI

N_loop_end:
	CMPQ SI, CX
	JL   N_loop

	RET

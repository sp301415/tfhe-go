//go:build amd64

#include "textflag.h"

TEXT ·DecomposeUint32PolyAssignAVX2(SB), NOSPLIT, $0-48
	MOVQ p+0(FP), AX
	MOVQ d+40(FP), BX

    MOVQ N+8(FP), CX
	MOVQ level+16(FP), DX

    MOVD base+24(FP), R10
    MOVD baseLog+28(FP), R11
    MOVD lastScaledBaseLog+32(FP), R12

    VPBROADCASTD R10, Y10 // base
    VPBROADCASTD R11, Y11 // baseLog
    VPBROADCASTD R12, Y12 // lastScaledBaseLog

    // Create (1, 1, 1, ..., 1)
    MOVD $1, R8
    VPBROADCASTD R8, Y0 // ONE

    VPSUBD Y0, Y10, Y13 // baseMask = base - 1
    VPSRLD $1, Y10, Y14 // baseHalf = base / 2
    VPSUBD Y0, Y11, Y15 // baseLog - 1
    VPSUBD Y0, Y12, Y9  // lastScaledBaseLog - 1

    XORQ SI, SI
    JMP N_loop_end

N_loop:
    // x := p[i]
    VMOVDQU (AX)(SI*4), Y1

    // c := ((x >> lsbl) + ((x >> (lsbl - 1)) & 1)) << lsbl
    // x >> (lsbl - 1)
    VPSRLVD Y9, Y1, Y3
    // c := x >> lsbl
    VPSRLD $1, Y3, Y2
    // (x >> (lsbl - 1) & 1)
    VPANDD Y3, Y0, Y3
    // c := (x >> lsbl) + (x >> (lsbl - 1) & 1)
    VPADDD Y2, Y3, Y1

    MOVQ DX, DI
    DECQ DI

    MOVQ DI, R10
    IMULQ $3, R10
    JMP level_loop_end

    level_loop:
        // d[j].Coeffs[i] = c & baseMask
        VPANDD Y1, Y13, Y2 // d[j].Coeffs[i]
        // c >>= baseLog
        VPSRLVD Y11, Y1, Y1
        // c += d[j].Coeffs[i] >> (baseLog - 1)
        VPSRLVD Y15, Y2, Y3
        VPADDD Y3, Y1, Y1
        // d[j].Coeffs[i] -= (d[j].Coeffs[i] & baseHalf) << 1
        VPANDD Y2, Y14, Y3
        VPSLLD $1, Y3, Y3
        VPSUBD Y3, Y2, Y2

        MOVQ (BX)(R10*8), R11
        VMOVDQU Y2, (R11)(SI*4)

        DECQ DI
        SUBQ $3, R10

    level_loop_end:
        CMPQ DI, $0
        JGE level_loop

    ADDQ $8, SI

N_loop_end:
    CMPQ SI, CX
    JL N_loop

	RET

TEXT ·DecomposeUint64PolyAssignAVX2(SB), NOSPLIT, $0-56
	MOVQ p+0(FP), AX
	MOVQ d+48(FP), BX

    MOVQ N+8(FP), CX
	MOVQ level+16(FP), DX

    MOVQ base+24(FP), R10
    MOVQ baseLog+32(FP), R11
    MOVQ lastScaledBaseLog+40(FP), R12

    VPBROADCASTQ R10, Y10 // base
    VPBROADCASTQ R11, Y11 // baseLog
    VPBROADCASTQ R12, Y12 // lastScaledBaseLog

    // Create (1, 1, 1, ..., 1)
    MOVQ $1, R8
    VPBROADCASTQ R8, Y0 // ONE

    VPSUBQ Y0, Y10, Y13 // baseMask = base - 1
    VPSRLQ $1, Y10, Y14 // baseHalf = base / 2
    VPSUBQ Y0, Y11, Y15 // baseLog - 1
    VPSUBQ Y0, Y12, Y9  // lastScaledBaseLog - 1

    XORQ SI, SI
    JMP N_loop_end

N_loop:
    // x := p[i]
    VMOVDQU (AX)(SI*8), Y1

    // c := ((x >> lsbl) + ((x >> (lsbl - 1)) & 1)) << lsbl
    // x >> (lsbl - 1)
    VPSRLVQ Y9, Y1, Y3
    // c := x >> lsbl
    VPSRLQ $1, Y3, Y2
    // (x >> (lsbl - 1) & 1)
    VPANDQ Y3, Y0, Y3
    // c := (x >> lsbl) + (x >> (lsbl - 1) & 1)
    VPADDQ Y2, Y3, Y1

    MOVQ DX, DI
    DECQ DI

    MOVQ DI, R10
    IMULQ $3, R10
    JMP level_loop_end

    level_loop:
        // d[j].Coeffs[i] = c & baseMask
        VPANDQ Y1, Y13, Y2 // d[j].Coeffs[i]
        // c >>= baseLog
        VPSRLVQ Y11, Y1, Y1
        // c += d[j].Coeffs[i] >> (baseLog - 1)
        VPSRLVQ Y15, Y2, Y3
        VPADDQ Y3, Y1, Y1
        // d[j].Coeffs[i] -= (d[j].Coeffs[i] & baseHalf) << 1
        VPANDQ Y2, Y14, Y3
        VPSLLQ $1, Y3, Y3
        VPSUBQ Y3, Y2, Y2

        MOVQ (BX)(R10*8), R11
        VMOVDQU Y2, (R11)(SI*8)

        DECQ DI
        SUBQ $3, R10

    level_loop_end:
        CMPQ DI, $0
        JGE level_loop

    ADDQ $4, SI

N_loop_end:
    CMPQ SI, CX
    JL N_loop

	RET

//go:build amd64

#include "textflag.h"

DATA one32<>+0(SB)/4, $0x1
GLOBL one32<>+0(SB), RODATA, $4
DATA one64<>+0(SB)/8, $0x1
GLOBL one64<>+0(SB), RODATA, $8


TEXT ·DecomposeUint32PolyAssignAVX2(SB), NOSPLIT, $0-48
	MOVQ pPtr+0(FP), AX
	MOVQ dPtr+40(FP), BX

    MOVQ (AX), AX
    MOVQ (BX), BX

    MOVQ N+8(FP), CX
	MOVQ level+16(FP), DX

    VPBROADCASTD base+24(FP), Y10               // base
    VPBROADCASTD baseLog+28(FP), Y11            // baseLog
    VPBROADCASTD lastScaledBaseLog+32(FP), Y12  // lastScaledBaseLog

    // Create (1, 1, 1, ..., 1)
    VPBROADCASTD one32<>(SB), Y0 // ONE

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
    VANDPD Y3, Y0, Y3
    // c := (x >> lsbl) + (x >> (lsbl - 1) & 1)
    VPADDD Y2, Y3, Y1

    MOVQ DX, DI
    DECQ DI

    MOVQ DI, R10
    ADDQ DI, R10
    ADDQ DI, R10 // R10 = DI * 3
    JMP level_loop_end

    level_loop:
        // d[j].Coeffs[i] = c & baseMask
        VANDPD Y1, Y13, Y2 // d[j].Coeffs[i]
        // c >>= baseLog
        VPSRLVD Y11, Y1, Y1
        // c += d[j].Coeffs[i] >> (baseLog - 1)
        VPSRLVD Y15, Y2, Y3
        VPADDD Y3, Y1, Y1
        // d[j].Coeffs[i] -= (d[j].Coeffs[i] & baseHalf) << 1
        VANDPD Y2, Y14, Y3
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
	MOVQ pPtr+0(FP), AX
	MOVQ dPtr+48(FP), BX

    MOVQ (AX), AX
    MOVQ (BX), BX

    MOVQ N+8(FP), CX
	MOVQ level+16(FP), DX

    VPBROADCASTQ base+24(FP), Y10               // base
    VPBROADCASTQ baseLog+32(FP), Y11            // baseLog
    VPBROADCASTQ lastScaledBaseLog+40(FP), Y12  // lastScaledBaseLog

    // Create (1, 1, 1, ..., 1)
    VPBROADCASTQ one64<>(SB), Y0 // ONE

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
    VANDPD Y3, Y0, Y3
    // c := (x >> lsbl) + (x >> (lsbl - 1) & 1)
    VPADDQ Y2, Y3, Y1

    MOVQ DX, DI
    DECQ DI

    MOVQ DI, R10
    ADDQ DI, R10
    ADDQ DI, R10 // R10 = DI * 3
    JMP level_loop_end

    level_loop:
        // d[j].Coeffs[i] = c & baseMask
        VANDPD Y1, Y13, Y2 // d[j].Coeffs[i]
        // c >>= baseLog
        VPSRLVQ Y11, Y1, Y1
        // c += d[j].Coeffs[i] >> (baseLog - 1)
        VPSRLVQ Y15, Y2, Y3
        VPADDQ Y3, Y1, Y1
        // d[j].Coeffs[i] -= (d[j].Coeffs[i] & baseHalf) << 1
        VANDPD Y2, Y14, Y3
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

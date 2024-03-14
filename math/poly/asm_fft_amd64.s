//go:build amd64 && !purego

#include "textflag.h"

TEXT ·fftInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ coeffs_base+0(FP), AX
	MOVQ tw_base+24(FP), BX

	MOVQ coeffs_len+8(FP), CX

	// First Loop
	MOVQ CX, DX
	SHRQ $1, DX // N/2

	VBROADCASTSD (BX), Y13  // Wr
	VBROADCASTSD 8(BX), Y14 // Wi
	ADDQ         $16, BX

	XORQ SI, SI         // j
	XORQ DI, DI
	ADDQ DX, DI         // j + N/2
	JMP  first_loop_end

first_loop:
	VMOVUPD (AX)(SI*8), Y0   // Ur
	VMOVUPD 32(AX)(SI*8), Y1 // Ui
	VMOVUPD (AX)(DI*8), Y2   // Vr
	VMOVUPD 32(AX)(DI*8), Y3 // Vi

	// V * W
	VMULPD      Y3, Y14, Y4
	VFMSUB231PD Y2, Y13, Y4 // Vr * W

	VMULPD      Y2, Y14, Y5
	VFMADD231PD Y3, Y13, Y5 // Vi * W

	VADDPD Y4, Y0, Y6
	VADDPD Y5, Y1, Y7
	VSUBPD Y4, Y0, Y8
	VSUBPD Y5, Y1, Y9

	VMOVUPD Y6, (AX)(SI*8)
	VMOVUPD Y7, 32(AX)(SI*8)
	VMOVUPD Y8, (AX)(DI*8)
	VMOVUPD Y9, 32(AX)(DI*8)

	ADDQ $8, SI
	ADDQ $8, DI

first_loop_end:
	CMPQ SI, DX
	JL   first_loop

	// Main loop
	// t := N >> 1
	MOVQ DX, R8 // t

	MOVQ $2, SI     // m
	SHRQ $2, DX     // N/8
	JMP  m_loop_end

m_loop:
	// t >>= 1
	SHRQ $1, R8

	XORQ DI, DI     // i
	JMP  i_loop_end

i_loop:
	// j1 := i * t << 1
	MOVQ  DI, R9 // j = j1
	IMULQ R8, R9
	ADDQ  R9, R9

	// j2 := j1 + t
	MOVQ R9, R11 // j2
	ADDQ R8, R11

	MOVQ R11, R10 // j + t

	VBROADCASTSD (BX), Y13  // Wr
	VBROADCASTSD 8(BX), Y14 // Wi
	ADDQ         $16, BX

	JMP j_loop_end

j_loop:
	VMOVUPD (AX)(R9*8), Y0    // Ur
	VMOVUPD 32(AX)(R9*8), Y1  // Ui
	VMOVUPD (AX)(R10*8), Y2   // Vr
	VMOVUPD 32(AX)(R10*8), Y3 // Vi

	// V * W
	VMULPD      Y3, Y14, Y4
	VFMSUB231PD Y2, Y13, Y4 // Vr * W

	VMULPD      Y2, Y14, Y5
	VFMADD231PD Y3, Y13, Y5 // Vi * W

	VADDPD Y4, Y0, Y6
	VADDPD Y5, Y1, Y7
	VSUBPD Y4, Y0, Y8
	VSUBPD Y5, Y1, Y9

	VMOVUPD Y6, (AX)(R9*8)
	VMOVUPD Y7, 32(AX)(R9*8)
	VMOVUPD Y8, (AX)(R10*8)
	VMOVUPD Y9, 32(AX)(R10*8)

	ADDQ $8, R9
	ADDQ $8, R10

j_loop_end:
	CMPQ R9, R11
	JL   j_loop

	ADDQ $1, DI

i_loop_end:
	CMPQ DI, SI
	JL   i_loop

	ADDQ SI, SI

m_loop_end:
	CMPQ SI, DX
	JL   m_loop

	// Last two loops
	// Last Loop - stride 2

	XORQ SI, SI          // j
	JMP  last_loop_2_end

last_loop_2:
	VMOVUPD (BX), X10
	VSHUFPD $0b00, X10, X10, X13 // Wr
	VSHUFPD $0b11, X10, X10, X14 // Wi
	ADDQ    $16, BX

	VMOVUPD (AX)(SI*8), X0   // Ur
	VMOVUPD 16(AX)(SI*8), X1 // Vr
	VMOVUPD 32(AX)(SI*8), X2 // Ui
	VMOVUPD 48(AX)(SI*8), X3 // Vi

	VMULPD      X3, X14, X4
	VFMSUB231PD X1, X13, X4 // Vr * W

	VMULPD      X3, X13, X5
	VFMADD231PD X1, X14, X5 // Vi * W

	VADDPD X4, X0, X6
	VSUBPD X4, X0, X7

	VADDPD X5, X2, X8
	VSUBPD X5, X2, X9

	VMOVUPD X6, (AX)(SI*8)
	VMOVUPD X7, 16(AX)(SI*8)
	VMOVUPD X8, 32(AX)(SI*8)
	VMOVUPD X9, 48(AX)(SI*8)

	ADDQ $8, SI

last_loop_2_end:
	CMPQ SI, CX
	JL   last_loop_2

	// Last Loop - stride 1
	VPXOR Y10, Y10, Y10 // (0, 0, 0, 0)

	XORQ SI, SI          // j
	JMP  last_loop_1_end

last_loop_1:
	VMOVUPD (BX), Y13              // (Wr0, Wi0, Wr1, Wi1)
	VSHUFPD $0b0101, Y13, Y13, Y14
	ADDQ    $32, BX

	VMOVUPD (AX)(SI*8), Y0   // (Ur0, Vr0, Ur1, Vr1)
	VMOVUPD 32(AX)(SI*8), Y1 // (Ui0, Vi0, Ui1, Vi1)

	VSHUFPD $0b1111, Y0, Y0, Y2 // (Vr0, Vr0, Vr1, Vr1)
	VSHUFPD $0b1111, Y1, Y1, Y3 // (Vi0, Vi0, Vi1, Vi1)

	VMULPD         Y3, Y14, Y5
	VFMADDSUB231PD Y2, Y13, Y5 // (Vr0 * W, Vi0 * W, Vr1 * W, Vi1 * W)

	VSHUFPD $0b0000, Y0, Y0, Y6 // (Ur0, Ur0, Ur1, Ur1)
	VSHUFPD $0b0000, Y1, Y1, Y7 // (Ui0, Ui0, Ui1, Ui1)

	VSHUFPD $0b0000, Y5, Y5, Y0 // (Vr0 * W, Vr0 * W, Vr1 * W, Vr1 * W)
	VSHUFPD $0b1111, Y5, Y5, Y1 // (Vi0 * W, Vi0 * W, Vi1 * W, Vi1 * W)
	VSUBPD  Y0, Y10, Y0
	VSUBPD  Y1, Y10, Y1

	VADDSUBPD Y0, Y6, Y0
	VADDSUBPD Y1, Y7, Y1

	VMOVUPD Y0, (AX)(SI*8)
	VMOVUPD Y1, 32(AX)(SI*8)

	ADDQ $8, SI

last_loop_1_end:
	CMPQ SI, CX
	JL   last_loop_1

	RET

TEXT ·invFFTInPlaceAVX2(SB), NOSPLIT, $0-56
	MOVQ coeffs_base+0(FP), AX
	MOVQ twInv_base+24(FP), BX

	MOVQ coeffs_len+8(FP), CX

	// First two loops
	// First Loop - stride 1
	XORQ SI, SI           // j
	JMP  first_loop_1_end

first_loop_1:
	VMOVUPD (BX), Y13              // (Wr0, Wi0, Wr1, Wi1)
	VSHUFPD $0b0101, Y13, Y13, Y14
	ADDQ    $32, BX

	VMOVUPD (AX)(SI*8), Y0   // (Ur0, Vr0, Ur1, Vr1)
	VMOVUPD 32(AX)(SI*8), Y1 // (Ui0, Vi0, Ui1, Vi1)

	VHADDPD Y0, Y0, Y10
	VHADDPD Y1, Y1, Y11

	VSHUFPD $0b0000, Y1, Y0, Y2 // (Ur0, Ui0, Ur1, Ui1)
	VSHUFPD $0b1111, Y1, Y0, Y3 // (Vr0, Vi0, Vr1, Vi1)

	VSUBPD Y3, Y2, Y2 // (UVr0, UVi0, UVr1, UVi1)

	VSHUFPD $0b0000, Y2, Y2, Y3 // (UVr0, UVr0, UVr1, UVr1)
	VSHUFPD $0b1111, Y2, Y2, Y4 // (UVi0, UVi0, UVi1, UVi1)

	VMULPD         Y4, Y14, Y5
	VFMADDSUB231PD Y3, Y13, Y5 // (UVr0 * W, UVi0 * W, UVr1 * W, UVi1 * W)

	VSHUFPD $0b0000, Y5, Y10, Y6
	VSHUFPD $0b1111, Y5, Y11, Y7

	VMOVUPD Y6, (AX)(SI*8)
	VMOVUPD Y7, 32(AX)(SI*8)

	ADDQ $8, SI

first_loop_1_end:
	CMPQ SI, CX
	JL   first_loop_1

	// First Loop - stride 2
	XORQ SI, SI           // j
	JMP  first_loop_2_end

first_loop_2:
	VMOVUPD (BX), X10
	VSHUFPD $0b00, X10, X10, X13 // Wr
	VSHUFPD $0b11, X10, X10, X14 // Wi
	ADDQ    $16, BX

	VMOVUPD (AX)(SI*8), X0   // Ur
	VMOVUPD 16(AX)(SI*8), X1 // Vr
	VMOVUPD 32(AX)(SI*8), X2 // Ui
	VMOVUPD 48(AX)(SI*8), X3 // Vi

	VADDPD X1, X0, X10
	VADDPD X3, X2, X11

	VSUBPD X1, X0, X4
	VSUBPD X3, X2, X5

	VMULPD      X5, X14, X6
	VFMSUB231PD X4, X13, X6 // Vr * W

	VMULPD      X5, X13, X7
	VFMADD231PD X4, X14, X7 // Vi * W

	VMOVUPD X10, (AX)(SI*8)
	VMOVUPD X6, 16(AX)(SI*8)
	VMOVUPD X11, 32(AX)(SI*8)
	VMOVUPD X7, 48(AX)(SI*8)

	ADDQ $8, SI

first_loop_2_end:
	CMPQ SI, CX
	JL   first_loop_2

	// Main Loop
	// t := 8
	MOVQ $8, R8 // t

	MOVQ CX, SI
	SHRQ $3, SI     // m = N/8
	JMP  m_loop_end

m_loop:
	// j1 := 0
	XORQ R9, R9 // j1

	XORQ DI, DI     // i
	JMP  i_loop_end

i_loop:
	// j2 := j1 + t
	MOVQ R9, R12
	ADDQ R8, R12 // j2

	MOVQ R9, R10 // j
	MOVQ R9, R11
	ADDQ R8, R11 // j + t

	VBROADCASTSD (BX), Y13  // Wr
	VBROADCASTSD 8(BX), Y14 // Wi
	ADDQ         $16, BX

j_loop:
	VMOVUPD (AX)(R10*8), Y0   // Ur
	VMOVUPD 32(AX)(R10*8), Y1 // Ui
	VMOVUPD (AX)(R11*8), Y2   // Vr
	VMOVUPD 32(AX)(R11*8), Y3 // Vi

	VADDPD Y2, Y0, Y4
	VADDPD Y3, Y1, Y5

	VSUBPD Y2, Y0, Y6 // UVr
	VSUBPD Y3, Y1, Y7 // UVi

	// UV * W
	VMULPD      Y7, Y14, Y8
	VFMSUB231PD Y6, Y13, Y8 // UVr * W

	VMULPD      Y6, Y14, Y9
	VFMADD231PD Y7, Y13, Y9 // UVi * W

	VMOVUPD Y4, (AX)(R10*8)
	VMOVUPD Y5, 32(AX)(R10*8)
	VMOVUPD Y8, (AX)(R11*8)
	VMOVUPD Y9, 32(AX)(R11*8)

	ADDQ $8, R10
	ADDQ $8, R11

j_loop_end:
	CMPQ R10, R12
	JL   j_loop

	// j1 += t << 1
	ADDQ R8, R9
	ADDQ R8, R9

	ADDQ $2, DI

i_loop_end:
	CMPQ DI, SI
	JL   i_loop

	// t <<= 1
	ADDQ R8, R8

	SHRQ $1, SI

m_loop_end:
	CMPQ SI, $2
	JG   m_loop

	// Last Loop
	MOVQ CX, DX
	SHRQ $1, DX // N/2

	VBROADCASTSD NInv+48(FP), Y12
	VBROADCASTSD (BX), Y13
	VBROADCASTSD 8(BX), Y14

	XORQ SI, SI        // j
	XORQ DI, DI
	ADDQ DX, DI        // j + N/2
	JMP  last_loop_end

last_loop:
	VMOVUPD (AX)(SI*8), Y0   // Ur
	VMOVUPD 32(AX)(SI*8), Y1 // Ui
	VMOVUPD (AX)(DI*8), Y2   // Vr
	VMOVUPD 32(AX)(DI*8), Y3 // Vi

	VADDPD Y2, Y0, Y4
	VADDPD Y3, Y1, Y5

	VMULPD Y4, Y12, Y4
	VMULPD Y5, Y12, Y5

	VSUBPD Y2, Y0, Y6 // UVr
	VSUBPD Y3, Y1, Y7 // UVi

	// UV * W
	VMULPD      Y7, Y14, Y8
	VFMSUB231PD Y6, Y13, Y8 // UVr * W

	VMULPD      Y6, Y14, Y9
	VFMADD231PD Y7, Y13, Y9 // UVi * W

	VMOVUPD Y4, (AX)(SI*8)
	VMOVUPD Y5, 32(AX)(SI*8)
	VMOVUPD Y8, (AX)(DI*8)
	VMOVUPD Y9, 32(AX)(DI*8)

	ADDQ $8, SI
	ADDQ $8, DI

last_loop_end:
	CMPQ SI, DX
	JL   last_loop

	RET

TEXT ·floatModTInPlaceAVX2(SB), NOSPLIT, $0-40
	MOVQ coeffs_base+0(FP), AX

	MOVQ coeffs_len+8(FP), DX

	VBROADCASTSD maxT+24(FP), Y10
	VBROADCASTSD maxTInv+32(FP), Y11

	XORQ SI, SI
	JMP  loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0

	VMULPD   Y0, Y11, Y0
	VROUNDPD $0, Y0, Y1
	VSUBPD   Y1, Y0, Y1
	VMULPD   Y1, Y10, Y1
	VROUNDPD $0, Y1, Y2

	VMOVUPD Y2, (AX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL   loop_body

	RET

//go:build amd64 && !purego

#include "textflag.h"

TEXT ·fftInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ coeffs+0(FP), AX
	MOVQ wNj+24(FP), BX

	MOVQ coeffs_len+8(FP), CX

	// First Loop
	// U, V := coeffs[j], coeffs[j+N]
	// coeffs[j], coeffs[j+N] = U+V, U-V

	XORQ SI, SI // j
	MOVQ SI, DI
	ADDQ CX, DI // j+N
	JMP first_loop_end

first_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(SI*8), Y2

	// V := coeffs[j+N]
	VMOVUPD (AX)(DI*8), Y3

	// coeffs[j] = U + V
	VADDPD Y3, Y2, Y4
	VMOVUPD Y4, (AX)(SI*8)

	// coeffs[j+N] = U - V
	VSUBPD Y3, Y2, Y4
	VMOVUPD Y4, (AX)(DI*8)

	ADDQ $4, SI
	ADDQ $4, DI

first_loop_end:
	CMPQ SI, CX
	JL first_loop

	// Main Loop
	// Start with wNj[1]
	ADDQ $16, BX

	// t := 2N
	MOVQ CX, R8

	MOVQ CX, DX
	SHRQ $1, DX // N/2

	MOVQ $2, R10 // m
	JMP m_loop_end

m_loop:
	// t >>= 1
	SHRQ $1, R8

	XORQ R11, R11 // i
	JMP i_loop_end

	i_loop:
		// Load wNj[m+i]
		ADDQ $16, BX
		VBROADCASTSD (BX), Y0
		VBROADCASTSD 8(BX), Y1

		// j = j1 := i*t << 1
		MOVQ R11, R12
		IMULQ R8, R12
		ADDQ R12, R12

		// j2 := j1 + t
		MOVQ R12, R14
		ADDQ R8, R14

		MOVQ R12, R15
		ADDQ R8, R15  // j + t
		JMP j_loop_end

		j_loop:
			// U := coeffs[j]
			VMOVUPD (AX)(R12*8), Y2

			// V := coeffs[j+t]
			VMOVUPD (AX)(R15*8), Y3

			// V = V * wNj[m+i]
			VSHUFPD        $0b0101, Y3, Y3, Y4
			VMULPD         Y1, Y4, Y4
			VFMADDSUB231PD Y0, Y3, Y4

			// coeffs[j] = U + V
			VADDPD Y4, Y2, Y5
			VMOVUPD Y5, (AX)(R12*8)

			// coeffs[j] = U - V
			VSUBPD Y4, Y2, Y5
			VMOVUPD Y5, (AX)(R15*8)

			ADDQ $4, R12
			ADDQ $4, R15

		j_loop_end:
			CMPQ R12, R14
			JL j_loop

		ADDQ $1, R11

	i_loop_end:
		CMPQ R11, R10
		JL i_loop

	// m <<= 1
	ADDQ R10, R10

m_loop_end:
	CMPQ R10, DX
	JL m_loop

	// Last Loop
	// U, V := coeffs[j], coeffs[j+1]*wNj[j+N]
	// coeffs[j], coeffs[j+1] = U+V, U-V

	MOVQ CX, DX
	ADDQ CX, DX // 2N

	XORQ SI, SI // j
	JMP last_loop_end

last_loop:
	// Load wNj[j+N]
	ADDQ $16, BX
	VMOVUPD (BX), X2
	VSHUFPD $0b00, X2, X2, X0
	VSHUFPD $0b11, X2, X2, X1

	// U := coeffs[j]
	VMOVUPD (AX)(SI*8), X2

	// V := coeffs[j+1]
	VMOVUPD 16(AX)(SI*8), X3

	// V = V * wNj[j+N]
	VSHUFPD        $0b01, X3, X3, X4
	VMULPD         X1, X4, X4
	VFMADDSUB231PD X0, X3, X4

	// coeffs[j] = U + V
	VADDPD X4, X2, X5
	VMOVUPD X5, (AX)(SI*8)

	// coeffs[j+1] = U - V
	VSUBPD X4, X2, X5
	VMOVUPD X5, 16(AX)(SI*8)

	ADDQ $4, SI

last_loop_end:
	CMPQ SI, DX
	JL last_loop

	RET

TEXT ·invFFTInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ coeffs+0(FP), AX
	MOVQ wNjInv+24(FP), BX

	MOVQ coeffs_len+8(FP), CX

	// First Loop
	// U, V := coeffs[j], coeffs[j+1]
	// coeffs[j], coeffs[j+1] = U+V, (U-V)*wNj[i]
	// Start from wNj[-1]
	SUBQ $16, BX

	MOVQ CX, DX
	ADDQ CX, DX // 2N

	XORQ SI, SI // j

	JMP first_loop_end

first_loop:
	// Load wNj[i]
	ADDQ $16, BX
	VMOVUPD (BX), X2
	VSHUFPD $0b00, X2, X2, X0
	VSHUFPD $0b11, X2, X2, X1

	// U := coeffs[j]
	VMOVUPD (AX)(SI*8), X2

	// V := coeffs[j+1]
	VMOVUPD 16(AX)(SI*8), X3

	// coeffs[j] = U + V
	VADDPD X3, X2, X4
	VMOVUPD X4, (AX)(SI*8)

	// coeffs[j+1] = U - V
	VSUBPD X3, X2, X4

	// coeffs[j+1] = coeffs[j+1] * wNj[i]
	VSHUFPD        $0b01, X4, X4, X5
	VMULPD         X1, X5, X5
	VFMADDSUB231PD X0, X4, X5
	VMOVUPD X5, 16(AX)(SI*8)

	ADDQ $4, SI

first_loop_end:
	CMPQ SI, DX
	JL first_loop

	// Main Loop
	// t := 4
	MOVQ $4, R8

	MOVQ CX, R10
	SHRQ $1, R10 // m
	JMP m_loop_end

m_loop:
	// j1 := 0
	XORQ R13, R13

	// h := m >> 1
	MOVQ R10, R9
	SHRQ $1, R9

	XORQ R11, R11 // i
	JMP i_loop_end

	i_loop:
		// Load wNjInv[k+i]
		ADDQ $16, BX
		VBROADCASTSD (BX), Y0
		VBROADCASTSD 8(BX), Y1

		// j2 := j1 + t
		MOVQ R13, R14
		ADDQ R8, R14

		MOVQ R13, R12 // j
		MOVQ R13, R15
		ADDQ R8, R15  // j + t
		JMP j_loop_end

		j_loop:
			// U := coeffs[j]
			VMOVUPD (AX)(R12*8), Y2

			// V := coeffs[j+t]
			VMOVUPD (AX)(R15*8), Y3

			// coeffs[j] = U + V
			VADDPD Y3, Y2, Y4
			VMOVUPD Y4, (AX)(R12*8)

			// U - V
			VSUBPD Y3, Y2, Y4

			// coeffs[j+t] = (U - V) * wNjInv[k+i]
			VSHUFPD        $0b0101, Y4, Y4, Y5
			VMULPD         Y1, Y5, Y5
			VFMADDSUB231PD Y0, Y4, Y5
			VMOVUPD Y5, (AX)(R15*8)

			ADDQ $4, R12
			ADDQ $4, R15

		j_loop_end:
			CMPQ R12, R14
			JL j_loop

		// j1 += t << 1
		ADDQ R8, R13
		ADDQ R8, R13

		ADDQ $1, R11

	i_loop_end:
		CMPQ R11, R9
		JL i_loop

	// t <<= 1
	ADDQ R8, R8

	SHRQ $1, R10

m_loop_end:
	CMPQ R10, $2
	JG m_loop

	// Last Loop
	// U, V := coeffs[j], coeffs[j+N]
	// coeffs[j], coeffs[j+N] = U+V, U-V

	XORQ SI, SI // j
	MOVQ SI, DI
	ADDQ CX, DI // j+N
	JMP last_loop_end

last_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(SI*8), Y2

	// V := coeffs[j+N]
	VMOVUPD (AX)(DI*8), Y3

	// coeffs[j] = U + V
	VADDPD Y3, Y2, Y4
	VMOVUPD Y4, (AX)(SI*8)

	// coeffs[j+N] = U - V
	VSUBPD Y3, Y2, Y4
	VMOVUPD Y4, (AX)(DI*8)

	ADDQ $4, SI
	ADDQ $4, DI

last_loop_end:
	CMPQ SI, CX
	JL last_loop

	RET

TEXT ·untwistInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX

	MOVQ v0_len+8(FP), DX
	ADDQ DX, DX

	XORQ SI, SI
	JMP loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VSHUFPD $0b0101, Y1, Y1, Y2
	VSHUFPD $0b1111, Y0, Y0, Y3
	VSHUFPD $0b0000, Y0, Y0, Y4

	VMULPD Y2, Y3, Y5
	VFMADDSUB231PD Y1, Y4, Y5

	VROUNDPD $0, Y5, Y5

	VMOVUPD Y5, (AX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL loop_body

	RET

TEXT ·untwistAndScaleInPlaceAVX2(SB), NOSPLIT, $0-56
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX

	MOVQ v0+8(FP), DX
	ADDQ DX, DX

	VBROADCASTSD T+48(FP), Y10

	XORQ SI, SI
	JMP loop_end

loop_body:
	VMOVUPD (AX)(SI*8), Y0
	VMOVUPD (BX)(SI*8), Y1

	VSHUFPD $0b0101, Y1, Y1, Y2
	VSHUFPD $0b1111, Y0, Y0, Y3
	VSHUFPD $0b0000, Y0, Y0, Y4

	VMULPD Y2, Y3, Y5
	VFMADDSUB231PD Y1, Y4, Y5

	VROUNDPD $0, Y5, Y6
	VSUBPD Y6, Y5, Y5
	VMULPD Y5, Y10, Y5

	VMOVUPD Y5, (AX)(SI*8)

	ADDQ $4, SI

loop_end:
	CMPQ SI, DX
	JL loop_body

	RET

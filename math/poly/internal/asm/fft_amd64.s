//go:build amd64

#include "textflag.h"

// func fftInPlaceAVX2(coeffs []complex128, wNj []complex128)
// Requires: AVX, FMA3
TEXT ·fftInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ coeffs_base+0(FP), AX
	MOVQ wNj_base+24(FP), CX
	MOVQ coeffs_len+8(FP), DX
	MOVQ DX, BX
	SHRQ $0x01, BX
	MOVQ DX, SI
	ADDQ DX, SI

	// Move wNj by one index
	ADDQ $0x10, CX

	// Precompute wNj[1]
	VBROADCASTSD (CX), Y0
	VBROADCASTSD 8(CX), Y1

	// First Loop
	// for j := 0; j < N/2; j++
	XORQ DI, DI
	JMP  first_loop_end

first_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(DI*8), Y2

	// V := coeffs[j+N/2]
	MOVQ    DI, R8
	ADDQ    DX, R8
	VMOVUPD (AX)(R8*8), Y3

	// V *= wNj[1]
	VSHUFPD        $0x05, Y3, Y3, Y4
	VMULPD         Y1, Y4, Y4
	VFMADDSUB231PD Y0, Y3, Y4

	// coeffs[j] = U + V
	VADDPD  Y2, Y4, Y3
	VMOVUPD Y3, (AX)(DI*8)

	// coeffs[j+N/2] = U - V
	VSUBPD  Y4, Y2, Y3
	VMOVUPD Y3, (AX)(R8*8)

	// j++
	ADDQ $0x04, DI

	// j < N/2
first_loop_end:
	CMPQ DI, DX
	JL   first_loop

	// t := N / 4
	MOVQ BX, DX

	// for m := 2; m < N/2; m <<= 1
	MOVQ $0x00000002, R9
	JMP  m_loop_end

m_loop:
	// for i := 0; i < m; i++
	XORQ R10, R10
	JMP  i_loop_end

i_loop:
	// Move wNj by one index
	ADDQ $0x10, CX

	// Precompute wNj[m+i]
	VBROADCASTSD (CX), Y0
	VBROADCASTSD 8(CX), Y1

	// j1 := i * t << 1
	MOVQ  R10, DI
	IMULQ DX, DI
	SHLQ  $0x01, DI

	// j2 := j1 + t
	MOVQ DI, R11
	ADDQ DX, R11

	// We increment j by 4 every iteration
	// for j := j1; j < j2; j++
	JMP j_loop_end

j_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(DI*8), Y2

	// V := coeffs[j+t]
	MOVQ    DI, R8
	ADDQ    DX, R8
	VMOVUPD (AX)(R8*8), Y3

	// V *= wNj[m+i]
	VSHUFPD        $0x05, Y3, Y3, Y4
	VMULPD         Y1, Y4, Y4
	VFMADDSUB231PD Y0, Y3, Y4

	// coeffs[j] = U + V
	VADDPD  Y2, Y4, Y3
	VMOVUPD Y3, (AX)(DI*8)

	// coeffs[j+t] = U - V
	VSUBPD  Y4, Y2, Y3
	VMOVUPD Y3, (AX)(R8*8)

	// j += 4
	ADDQ $0x04, DI

	// j < j2
j_loop_end:
	CMPQ DI, R11
	JL   j_loop

	// i++
	INCQ R10

	// i < m
i_loop_end:
	CMPQ R10, R9
	JL   i_loop

	// t >>= 1
	SHRQ $0x01, DX

	// m <<= 1
	SHLQ $0x01, R9

	// m < N/2
m_loop_end:
	CMPQ R9, BX
	JL   m_loop

	// Last Loop
	// for j := 0; j < N; j += 2
	XORQ DI, DI
	JMP  last_loop_end

last_loop:
	// Move wNj by one index
	ADDQ $0x10, CX

	// Precompute wNj[m+i]
	VMOVUPD (CX), X0
	VSHUFPD $0x01, X0, X0, X1

	// U := coeffs[j]
	VMOVUPD (AX)(DI*8), X2

	// V := coeffs[j+1]
	VMOVUPD 16(AX)(DI*8), X3

	// V *= wNj[m+i]
	VSHUFPD        $0x03, X3, X3, X4
	VSHUFPD        $0x00, X3, X3, X3
	VMULPD         X4, X1, X1
	VFMADDSUB231PD X3, X0, X1

	// coeffs[j] = U + V
	VADDPD  X2, X1, X0
	VMOVUPD X0, (AX)(DI*8)

	// coeffs[j+1] = U - V
	VSUBPD  X1, X2, X0
	VMOVUPD X0, 16(AX)(DI*8)

	// j += 2
	ADDQ $0x04, DI

	// j < N
last_loop_end:
	CMPQ DI, SI
	JL   last_loop
	RET

// func invFFTInPlaceAVX2(coeffs []complex128, wNjInv []complex128)
// Requires: AVX, FMA3
TEXT ·invFFTInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ coeffs_base+0(FP), AX
	MOVQ wNjInv_base+24(FP), CX
	MOVQ coeffs_len+8(FP), DX
	MOVQ DX, BX
	ADDQ DX, BX
	MOVQ DX, SI
	SHRQ $0x01, SI

	// First Loop
	// hi := N / 2
	MOVQ DX, DI

	// for j := 0; j < N; j += 2
	XORQ R8, R8
	JMP  first_loop_end

first_loop:
	// Precompute wNjInv[hi]
	VMOVUPD (CX)(DI*8), X0
	VSHUFPD $0x01, X0, X0, X1

	// U := coeffs[j]
	VMOVUPD (AX)(R8*8), X2

	// V := coeffs[j+1]
	VMOVUPD 16(AX)(R8*8), X3

	// coeffs[j] = U + V
	VADDPD  X2, X3, X4
	VMOVUPD X4, (AX)(R8*8)

	// coeffs[j+1] = (U - V) * wNjInv[hi]
	VSUBPD         X3, X2, X4
	VSHUFPD        $0x03, X4, X4, X2
	VSHUFPD        $0x00, X4, X4, X3
	VMULPD         X2, X1, X1
	VFMADDSUB231PD X3, X0, X1
	VMOVUPD        X1, 16(AX)(R8*8)

	// hi++
	ADDQ $0x02, DI

	// j += 2
	ADDQ $0x04, R8

	// j < N
first_loop_end:
	CMPQ R8, BX
	JL   first_loop

	// t := 2
	MOVQ $0x00000004, BX

	// for m := N / 2; m > 2; m >>= 1
	JMP m_loop_end

m_loop:
	// j1 := 0
	XORQ R9, R9

	// h := m >> 1
	MOVQ SI, R10

	// for i := 0; i < h; i++
	XORQ R11, R11
	JMP  i_loop_end

i_loop:
	// Precompute wNjInv[h+i]
	MOVQ         R10, DI
	ADDQ         R11, DI
	VBROADCASTSD (CX)(DI*8), Y0
	VBROADCASTSD 8(CX)(DI*8), Y1

	// j2 := j1 + t
	MOVQ R9, DI
	ADDQ BX, DI

	// We increment j by 4 every iteration
	// for j := j1; j < j2; j++
	MOVQ R9, R8
	JMP  j_loop_end

j_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(R8*8), Y2

	// V := coeffs[j+t]
	MOVQ    R8, R12
	ADDQ    BX, R12
	VMOVUPD (AX)(R12*8), Y3

	// coeffs[j] = U + V
	VADDPD  Y2, Y3, Y4
	VMOVUPD Y4, (AX)(R8*8)

	// coeffs[j+t] = (U - V) * wNjInv[h+i]
	VSUBPD         Y3, Y2, Y4
	VSHUFPD        $0x05, Y4, Y4, Y2
	VMULPD         Y1, Y2, Y2
	VFMADDSUB231PD Y0, Y4, Y2
	VMOVUPD        Y2, (AX)(R12*8)

	// j += 4
	ADDQ $0x04, R8

	// j < j2
j_loop_end:
	CMPQ R8, DI
	JL   j_loop

	// j1 += t << 1
	MOVQ BX, DI
	SHLQ $0x01, DI
	ADDQ DI, R9

	// i++
	ADDQ $0x02, R11

	// i < h
i_loop_end:
	CMPQ R11, R10
	JL   i_loop

	// t <<= 1
	SHLQ $0x01, BX

	// m >>= 1
	SHRQ $0x01, SI

	// m > 2
m_loop_end:
	CMPQ SI, $0x00000002
	JG   m_loop

	// Last Loop
	// Precompute wNjInv[1]
	VBROADCASTSD 16(CX), Y0
	VBROADCASTSD 24(CX), Y1

	// for j := 0; j < N/2; j++
	XORQ R8, R8
	JMP  last_loop_end

last_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(R8*8), Y2

	// V := coeffs[j+N/2]
	MOVQ    R8, R12
	ADDQ    DX, R12
	VMOVUPD (AX)(R12*8), Y3

	// coeffs[j] = U + V
	VADDPD  Y2, Y3, Y4
	VMOVUPD Y4, (AX)(R8*8)

	// coeffs[j+N/2] = (U - V) * wNjInv[1]
	VSUBPD         Y3, Y2, Y4
	VSHUFPD        $0x05, Y4, Y4, Y2
	VMULPD         Y1, Y2, Y2
	VFMADDSUB231PD Y0, Y4, Y2
	VMOVUPD        Y2, (AX)(R12*8)

	// j++
	ADDQ $0x04, R8

	// j < N/2
last_loop_end:
	CMPQ R8, DX
	JL   last_loop
	RET

TEXT ·twistAndScaleInPlaceAVX2(SB), NOSPLIT, $0-56
	MOVQ v0+24(FP), AX
	MOVQ vOut+0(FP), BX

	MOVQ vOut_len+16(FP), DX
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

	VMULPD Y10, Y5, Y5

	VMOVUPD Y5, (BX)(SI*8)

	ADDQ $0x04, SI

loop_end:
	CMPQ SI, DX
	JL loop_body

	RET

TEXT ·untwistAssignAVX2(SB), NOSPLIT, $0-72
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+48(FP), CX

	MOVQ vOut_len+56(FP), DX
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

	VMOVUPD Y5, (CX)(SI*8)

	ADDQ $0x04, SI

loop_end:
	CMPQ SI, DX
	JL loop_body

	RET

TEXT ·untwistAndScaleAssignAVX2(SB), NOSPLIT, $0-80
	MOVQ v0+0(FP), AX
	MOVQ v1+24(FP), BX
	MOVQ vOut+56(FP), CX

	MOVQ vOut_len+72(FP), DX

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

	VMOVUPD Y5, (CX)(SI*8)

	ADDQ $0x04, SI

loop_end:
	CMPQ SI, DX
	JL loop_body

	RET

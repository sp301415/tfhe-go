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

	// t := N / 2
	// for m := 1; m < N/2; m <<= 1
	MOVQ $0x00000001, DI
	JMP  m_loop_end

m_loop:
	// for i := 0; i < m; i++
	XORQ R8, R8
	JMP  i_loop_end

i_loop:
	// Move wNj by one index
	ADDQ $0x10, CX

	// Precompute wNj[m+i]
	VBROADCASTF128 (CX), Y0
	VSHUFPD        $0x05, Y0, Y0, Y1

	// j1 := i * t << 1
	MOVQ  R8, R9
	IMULQ DX, R9
	SHLQ  $0x01, R9

	// j2 := j1 + t
	MOVQ R9, R10
	ADDQ DX, R10

	// We increment j by 4 every iteration
	// for j := j1; j < j2; j++
	JMP j_loop_end

j_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(R9*8), Y2

	// V := coeffs[j+t]
	MOVQ    R9, R11
	ADDQ    DX, R11
	VMOVUPD (AX)(R11*8), Y3

	// V *= wNj[m+i]
	VSHUFPD        $0x0f, Y3, Y3, Y4
	VSHUFPD        $0x00, Y3, Y3, Y3
	VMULPD         Y4, Y1, Y4
	VFMADDSUB231PD Y3, Y0, Y4

	// coeffs[j] = U + V
	VADDPD  Y2, Y4, Y3
	VMOVUPD Y3, (AX)(R9*8)

	// coeffs[j+t] = U - V
	VSUBPD  Y4, Y2, Y3
	VMOVUPD Y3, (AX)(R11*8)

	// j += 4
	ADDQ $0x04, R9

	// j < j2
j_loop_end:
	CMPQ R9, R10
	JL   j_loop

	// i++
	INCQ R8

	// i < m
i_loop_end:
	CMPQ R8, DI
	JL   i_loop

	// t >>= 1
	SHRQ $0x01, DX

	// m <<= 1
	SHLQ $0x01, DI

	// m < N/2
m_loop_end:
	CMPQ DI, BX
	JL   m_loop

	// Last Loop
	// for j := 0; j < N; j += 2
	XORQ R9, R9
	JMP  last_loop_end

last_loop:
	// Move wNj by one index
	ADDQ $0x10, CX

	// Precompute wNj[m+i]
	VMOVUPD (CX), X0
	VSHUFPD $0x01, X0, X0, X1

	// U := coeffs[j]
	VMOVUPD (AX)(R9*8), X2

	// V := coeffs[j+1]
	VMOVUPD 16(AX)(R9*8), X3

	// V *= wNj[m+i]
	VSHUFPD        $0x03, X3, X3, X4
	VSHUFPD        $0x00, X3, X3, X3
	VMULPD         X4, X1, X1
	VFMADDSUB231PD X3, X0, X1

	// coeffs[j] = U + V
	VADDPD  X2, X1, X0
	VMOVUPD X0, (AX)(R9*8)

	// coeffs[j+1] = U - V
	VSUBPD  X1, X2, X0
	VMOVUPD X0, 16(AX)(R9*8)

	// j += 2
	ADDQ $0x04, R9

	// j < N
last_loop_end:
	CMPQ R9, SI
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
	// for j := 0; j < N; j += 2
	XORQ DI, DI
	JMP  first_loop_end

first_loop:
	// Index wNjInv
	VMOVUPD (CX)(DX*8), X0

	// Precompute wNjInv[hi]
	VSHUFPD $0x01, X0, X0, X1

	// U := coeffs[j]
	VMOVUPD (AX)(DI*8), X2

	// V := coeffs[j+1]
	VMOVUPD 16(AX)(DI*8), X3

	// coeffs[j] = U + V
	VADDPD  X2, X3, X4
	VMOVUPD X4, (AX)(DI*8)

	// coeffs[j+1] = (U - V) * wNjInv[hi]
	VSUBPD         X3, X2, X4
	VSHUFPD        $0x03, X4, X4, X2
	VSHUFPD        $0x00, X4, X4, X3
	VMULPD         X2, X1, X1
	VFMADDSUB231PD X3, X0, X1
	VMOVUPD        X1, 16(AX)(DI*8)

	// hi++
	ADDQ $0x02, DX

	// j += 2
	ADDQ $0x04, DI

	// j < N
first_loop_end:
	CMPQ DI, BX
	JL   first_loop

	// t := 2
	MOVQ $0x00000004, BX

	// for m := N / 2; m > 1; m >>= 1
	JMP m_loop_end

m_loop:
	// j1 := 0
	XORQ R8, R8

	// h := m >> 1
	MOVQ SI, R9

	// for i := 0; i < h; i++
	XORQ R10, R10
	JMP  i_loop_end

i_loop:
	// Precompute wNjInv[h+i]
	MOVQ           R9, DX
	ADDQ           R10, DX
	VBROADCASTF128 (CX)(DX*8), Y0
	VSHUFPD        $0x05, Y0, Y0, Y1

	// j2 := j1 + t
	MOVQ R8, DX
	ADDQ BX, DX

	// We increment j by 4 every iteration
	// for j := j1; j < j2; j++
	MOVQ R8, DI
	JMP  j_loop_end

j_loop:
	// U := coeffs[j]
	VMOVUPD (AX)(DI*8), Y2

	// V := coeffs[j+t]
	MOVQ    DI, R11
	ADDQ    BX, R11
	VMOVUPD (AX)(R11*8), Y3

	// coeffs[j] = U + V
	VADDPD  Y2, Y3, Y4
	VMOVUPD Y4, (AX)(DI*8)

	// coeffs[j+t] = (U - V) * wNjInv[h+i]
	VSUBPD         Y3, Y2, Y4
	VSHUFPD        $0x0f, Y4, Y4, Y2
	VSHUFPD        $0x00, Y4, Y4, Y3
	VMULPD         Y2, Y1, Y2
	VFMADDSUB231PD Y3, Y0, Y2
	VMOVUPD        Y2, (AX)(R11*8)

	// j += 4
	ADDQ $0x04, DI

	// j < j2
j_loop_end:
	CMPQ DI, DX
	JL   j_loop

	// j1 += t << 1
	MOVQ BX, DX
	SHLQ $0x01, DX
	ADDQ DX, R8

	// i++
	ADDQ $0x02, R10

	// i < h
i_loop_end:
	CMPQ R10, R9
	JL   i_loop

	// t <<= 1
	SHLQ $0x01, BX

	// m >>= 1
	SHRQ $0x01, SI

	// m > 1
m_loop_end:
	CMPQ SI, $0x00000001
	JG   m_loop
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

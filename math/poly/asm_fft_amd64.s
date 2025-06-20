// Code generated by command: go run asmgen.go -fft -out ../../math/poly/asm_fft_amd64.s -stubs ../../math/poly/asm_fft_stub_amd64.go -pkg=poly. DO NOT EDIT.

//go:build amd64 && !purego

#include "textflag.h"

// func fftInPlaceAVX2(coeffs []float64, tw []complex128)
// Requires: AVX, FMA3
TEXT ·fftInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ         coeffs_base+0(FP), AX
	MOVQ         tw_base+24(FP), CX
	MOVQ         coeffs_len+8(FP), DX
	XORQ         BX, BX
	MOVQ         DX, SI
	SHRQ         $0x01, SI
	VBROADCASTSD (CX)(BX*8), Y0
	VBROADCASTSD 8(CX)(BX*8), Y1
	ADDQ         $0x02, BX
	XORQ         DI, DI
	MOVQ         SI, R8
	JMP          first_loop_end

first_loop_body:
	VMOVUPD      (AX)(DI*8), Y2
	VMOVUPD      32(AX)(DI*8), Y3
	VMOVUPD      (AX)(R8*8), Y4
	VMOVUPD      32(AX)(R8*8), Y5
	VMULPD       Y0, Y4, Y6
	VFNMADD231PD Y1, Y5, Y6
	VMULPD       Y1, Y4, Y7
	VFMADD231PD  Y0, Y5, Y7
	VSUBPD       Y6, Y2, Y4
	VSUBPD       Y7, Y3, Y5
	VADDPD       Y6, Y2, Y2
	VADDPD       Y7, Y3, Y3
	VMOVUPD      Y2, (AX)(DI*8)
	VMOVUPD      Y3, 32(AX)(DI*8)
	VMOVUPD      Y4, (AX)(R8*8)
	VMOVUPD      Y5, 32(AX)(R8*8)
	ADDQ         $0x08, DI
	ADDQ         $0x08, R8

first_loop_end:
	CMPQ DI, SI
	JL   first_loop_body
	MOVQ DX, SI
	SHRQ $0x04, SI
	MOVQ DX, R9
	SHRQ $0x01, R9
	MOVQ $0x0000000000000002, R10
	JMP  m_loop_end

m_loop_body:
	SHRQ $0x01, R9
	XORQ R11, R11
	JMP  i_loop_end

i_loop_body:
	MOVQ         R9, DI
	IMULQ        R11, DI
	SHLQ         $0x01, DI
	MOVQ         DI, R12
	ADDQ         R9, R12
	VBROADCASTSD (CX)(BX*8), Y0
	VBROADCASTSD 8(CX)(BX*8), Y1
	ADDQ         $0x02, BX
	MOVQ         R12, R8
	JMP          j_loop_end

j_loop_body:
	VMOVUPD      (AX)(DI*8), Y2
	VMOVUPD      32(AX)(DI*8), Y3
	VMOVUPD      (AX)(R8*8), Y4
	VMOVUPD      32(AX)(R8*8), Y5
	VMULPD       Y0, Y4, Y6
	VFNMADD231PD Y1, Y5, Y6
	VMULPD       Y1, Y4, Y7
	VFMADD231PD  Y0, Y5, Y7
	VSUBPD       Y6, Y2, Y4
	VSUBPD       Y7, Y3, Y5
	VADDPD       Y6, Y2, Y2
	VADDPD       Y7, Y3, Y3
	VMOVUPD      Y2, (AX)(DI*8)
	VMOVUPD      Y3, 32(AX)(DI*8)
	VMOVUPD      Y4, (AX)(R8*8)
	VMOVUPD      Y5, 32(AX)(R8*8)
	ADDQ         $0x08, DI
	ADDQ         $0x08, R8

j_loop_end:
	CMPQ DI, R12
	JL   j_loop_body
	ADDQ $0x01, R11

i_loop_end:
	CMPQ R11, R10
	JL   i_loop_body
	SHLQ $0x01, R10

m_loop_end:
	CMPQ R10, SI
	JLE  m_loop_body
	XORQ DI, DI
	JMP  last_loop_2_end

last_loop_2_body:
	VMOVUPD      (CX)(BX*8), X0
	VSHUFPD      $0x03, X0, X0, X1
	VSHUFPD      $0x00, X0, X0, X0
	ADDQ         $0x02, BX
	VMOVUPD      (AX)(DI*8), X2
	VMOVUPD      16(AX)(DI*8), X3
	VMOVUPD      32(AX)(DI*8), X4
	VMOVUPD      48(AX)(DI*8), X5
	VMULPD       X0, X3, X6
	VFNMADD231PD X1, X5, X6
	VMULPD       X1, X3, X1
	VFMADD231PD  X0, X5, X1
	VSUBPD       X6, X2, X3
	VSUBPD       X1, X4, X5
	VADDPD       X6, X2, X2
	VADDPD       X1, X4, X4
	VMOVUPD      X2, (AX)(DI*8)
	VMOVUPD      X3, 16(AX)(DI*8)
	VMOVUPD      X4, 32(AX)(DI*8)
	VMOVUPD      X5, 48(AX)(DI*8)
	ADDQ         $0x08, DI

last_loop_2_end:
	CMPQ   DI, DX
	JL     last_loop_2_body
	VXORPD Y0, Y0, Y0
	XORQ   DI, DI
	JMP    last_loop_1_end

last_loop_1_body:
	VMOVUPD        (CX)(BX*8), Y2
	VSHUFPD        $0x05, Y2, Y2, Y3
	ADDQ           $0x04, BX
	VMOVUPD        (AX)(DI*8), Y6
	VMOVUPD        32(AX)(DI*8), Y1
	VSHUFPD        $0x0f, Y6, Y6, Y4
	VSHUFPD        $0x0f, Y1, Y1, Y5
	VMULPD         Y3, Y5, Y5
	VFMADDSUB231PD Y2, Y4, Y5
	VSHUFPD        $0x00, Y6, Y6, Y2
	VSHUFPD        $0x00, Y1, Y1, Y3
	VSHUFPD        $0x00, Y5, Y5, Y1
	VSHUFPD        $0x0f, Y5, Y5, Y4
	VSUBPD         Y1, Y0, Y1
	VSUBPD         Y4, Y0, Y4
	VADDSUBPD      Y1, Y2, Y1
	VADDSUBPD      Y4, Y3, Y2
	VMOVUPD        Y1, (AX)(DI*8)
	VMOVUPD        Y2, 32(AX)(DI*8)
	ADDQ           $0x08, DI

last_loop_1_end:
	CMPQ DI, DX
	JL   last_loop_1_body
	RET

// func ifftInPlaceAVX2(coeffs []float64, twInv []complex128, scale float64)
// Requires: AVX, FMA3
TEXT ·ifftInPlaceAVX2(SB), NOSPLIT, $0-56
	MOVQ coeffs_base+0(FP), AX
	MOVQ twInv_base+24(FP), CX
	MOVQ coeffs_len+8(FP), DX
	XORQ BX, BX
	XORQ SI, SI
	JMP  first_loop_1_end

first_loop_1_body:
	VMOVUPD        (CX)(BX*8), Y0
	VSHUFPD        $0x05, Y0, Y0, Y1
	ADDQ           $0x04, BX
	VMOVUPD        (AX)(SI*8), Y2
	VMOVUPD        32(AX)(SI*8), Y3
	VHADDPD        Y2, Y2, Y4
	VHADDPD        Y3, Y3, Y5
	VSHUFPD        $0x00, Y3, Y2, Y6
	VSHUFPD        $0x0f, Y3, Y2, Y2
	VSUBPD         Y2, Y6, Y2
	VSHUFPD        $0x00, Y2, Y2, Y3
	VSHUFPD        $0x0f, Y2, Y2, Y2
	VMULPD         Y1, Y2, Y1
	VFMADDSUB231PD Y0, Y3, Y1
	VSHUFPD        $0x00, Y1, Y4, Y0
	VSHUFPD        $0x0f, Y1, Y5, Y1
	VMOVUPD        Y0, (AX)(SI*8)
	VMOVUPD        Y1, 32(AX)(SI*8)
	ADDQ           $0x08, SI

first_loop_1_end:
	CMPQ SI, DX
	JL   first_loop_1_body
	XORQ SI, SI
	JMP  first_loop_2_end

first_loop_2_body:
	VMOVUPD      (CX)(BX*8), X0
	VSHUFPD      $0x03, X0, X0, X1
	VSHUFPD      $0x00, X0, X0, X0
	ADDQ         $0x02, BX
	VMOVUPD      (AX)(SI*8), X2
	VMOVUPD      16(AX)(SI*8), X3
	VMOVUPD      32(AX)(SI*8), X4
	VMOVUPD      48(AX)(SI*8), X5
	VSUBPD       X3, X2, X6
	VADDPD       X3, X2, X2
	VSUBPD       X5, X4, X7
	VADDPD       X5, X4, X4
	VMULPD       X0, X6, X3
	VFNMADD231PD X1, X7, X3
	VMULPD       X1, X6, X5
	VFMADD231PD  X0, X7, X5
	VMOVUPD      X2, (AX)(SI*8)
	VMOVUPD      X3, 16(AX)(SI*8)
	VMOVUPD      X4, 32(AX)(SI*8)
	VMOVUPD      X5, 48(AX)(SI*8)
	ADDQ         $0x08, SI

first_loop_2_end:
	CMPQ SI, DX
	JL   first_loop_2_body
	MOVQ $0x0000000000000008, SI
	MOVQ DX, DI
	SHRQ $0x04, DI
	JMP  m_loop_end

m_loop_body:
	XORQ R8, R8
	JMP  i_loop_end

i_loop_body:
	MOVQ         SI, R9
	IMULQ        R8, R9
	SHLQ         $0x01, R9
	MOVQ         R9, R10
	ADDQ         SI, R10
	VBROADCASTSD (CX)(BX*8), Y0
	VBROADCASTSD 8(CX)(BX*8), Y1
	ADDQ         $0x02, BX
	MOVQ         R10, R11
	JMP          j_loop_end

j_loop_body:
	VMOVUPD      (AX)(R9*8), Y2
	VMOVUPD      32(AX)(R9*8), Y3
	VMOVUPD      (AX)(R11*8), Y4
	VMOVUPD      32(AX)(R11*8), Y5
	VSUBPD       Y4, Y2, Y6
	VADDPD       Y4, Y2, Y2
	VSUBPD       Y5, Y3, Y7
	VADDPD       Y5, Y3, Y3
	VMULPD       Y0, Y6, Y4
	VFNMADD231PD Y1, Y7, Y4
	VMULPD       Y1, Y6, Y5
	VFMADD231PD  Y0, Y7, Y5
	VMOVUPD      Y2, (AX)(R9*8)
	VMOVUPD      Y3, 32(AX)(R9*8)
	VMOVUPD      Y4, (AX)(R11*8)
	VMOVUPD      Y5, 32(AX)(R11*8)
	ADDQ         $0x08, R9
	ADDQ         $0x08, R11

j_loop_end:
	CMPQ R9, R10
	JL   j_loop_body
	ADDQ $0x01, R8

i_loop_end:
	CMPQ R8, DI
	JL   i_loop_body
	SHLQ $0x01, SI
	SHRQ $0x01, DI

m_loop_end:
	CMPQ         DI, $0x02
	JGE          m_loop_body
	VBROADCASTSD scale+48(FP), Y0
	VBROADCASTSD (CX)(BX*8), Y1
	VBROADCASTSD 8(CX)(BX*8), Y6
	MOVQ         DX, CX
	SHRQ         $0x01, CX
	XORQ         R9, R9
	MOVQ         CX, R11
	JMP          last_loop_end

last_loop_body:
	VMOVUPD      (AX)(R9*8), Y2
	VMOVUPD      32(AX)(R9*8), Y3
	VMOVUPD      (AX)(R11*8), Y4
	VMOVUPD      32(AX)(R11*8), Y5
	VSUBPD       Y4, Y2, Y7
	VADDPD       Y4, Y2, Y2
	VSUBPD       Y5, Y3, Y8
	VADDPD       Y5, Y3, Y3
	VMULPD       Y1, Y7, Y4
	VFNMADD231PD Y6, Y8, Y4
	VMULPD       Y6, Y7, Y5
	VFMADD231PD  Y1, Y8, Y5
	VMULPD       Y0, Y2, Y2
	VMULPD       Y0, Y3, Y3
	VMULPD       Y0, Y4, Y4
	VMULPD       Y0, Y5, Y5
	VMOVUPD      Y2, (AX)(R9*8)
	VMOVUPD      Y3, 32(AX)(R9*8)
	VMOVUPD      Y4, (AX)(R11*8)
	VMOVUPD      Y5, 32(AX)(R11*8)
	ADDQ         $0x08, R9
	ADDQ         $0x08, R11

last_loop_end:
	CMPQ R9, CX
	JL   last_loop_body
	RET

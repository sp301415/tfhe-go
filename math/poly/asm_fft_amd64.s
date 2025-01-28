// Code generated by command: go run asmgen.go -fft -out ../../math/poly/asm_fft_amd64.s -stubs ../../math/poly/asm_fft_stub_amd64.go -pkg=poly. DO NOT EDIT.

//go:build amd64 && !purego

#include "textflag.h"

// func fftInPlaceAVX2(coeffs []float64, tw []complex128)
// Requires: AVX, AVX2, FMA3
TEXT ·fftInPlaceAVX2(SB), NOSPLIT, $0-48
	MOVQ         coeffs_base+0(FP), AX
	MOVQ         tw_base+24(FP), CX
	MOVQ         coeffs_len+8(FP), DX
	XORQ         BX, BX
	VBROADCASTSD (CX)(BX*8), Y0
	VBROADCASTSD 8(CX)(BX*8), Y1
	ADDQ         $0x02, BX
	MOVQ         DX, SI
	SHRQ         $0x01, SI
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
	VMULPD       Y1, Y4, Y4
	VFMADD231PD  Y0, Y5, Y4
	VADDPD       Y6, Y2, Y5
	VADDPD       Y4, Y3, Y7
	VSUBPD       Y6, Y2, Y2
	VSUBPD       Y4, Y3, Y3
	VMOVUPD      Y5, (AX)(DI*8)
	VMOVUPD      Y7, 32(AX)(DI*8)
	VMOVUPD      Y2, (AX)(R8*8)
	VMOVUPD      Y3, 32(AX)(R8*8)
	ADDQ         $0x08, DI
	ADDQ         $0x08, R8

first_loop_end:
	CMPQ DI, SI
	JL   first_loop_body
	MOVQ DX, DI
	SHRQ $0x03, DI
	MOVQ $0x0000000000000002, R8
	JMP  main_loop_end

main_loop_body:
	SHRQ $0x01, SI
	XORQ R9, R9
	JMP  i_loop_end

i_loop_body:
	MOVQ         SI, R10
	IMULQ        R9, R10
	SHLQ         $0x01, R10
	MOVQ         R10, R11
	ADDQ         SI, R11
	VBROADCASTSD (CX)(BX*8), Y0
	VBROADCASTSD 8(CX)(BX*8), Y1
	ADDQ         $0x02, BX
	MOVQ         R11, R12
	JMP          j_loop_end

j_loop_body:
	VMOVUPD      (AX)(R10*8), Y2
	VMOVUPD      32(AX)(R10*8), Y3
	VMOVUPD      (AX)(R12*8), Y4
	VMOVUPD      32(AX)(R12*8), Y5
	VMULPD       Y0, Y4, Y6
	VFNMADD231PD Y1, Y5, Y6
	VMULPD       Y1, Y4, Y4
	VFMADD231PD  Y0, Y5, Y4
	VADDPD       Y6, Y2, Y5
	VADDPD       Y4, Y3, Y7
	VSUBPD       Y6, Y2, Y2
	VSUBPD       Y4, Y3, Y3
	VMOVUPD      Y5, (AX)(R10*8)
	VMOVUPD      Y7, 32(AX)(R10*8)
	VMOVUPD      Y2, (AX)(R12*8)
	VMOVUPD      Y3, 32(AX)(R12*8)
	ADDQ         $0x08, R10
	ADDQ         $0x08, R12

j_loop_end:
	CMPQ R10, R11
	JL   j_loop_body
	ADDQ $0x01, R9

i_loop_end:
	CMPQ R9, R8
	JL   i_loop_body
	SHLQ $0x01, R8

main_loop_end:
	CMPQ R8, DI
	JL   main_loop_body
	XORQ SI, SI
	JMP  last_loop_2_end

last_loop_2_body:
	VMOVUPD      (CX)(BX*8), X0
	VSHUFPD      $0x00, X0, X0, X1
	VSHUFPD      $0x03, X0, X0, X0
	ADDQ         $0x02, BX
	VMOVUPD      (AX)(SI*8), X2
	VMOVUPD      16(AX)(SI*8), X3
	VMOVUPD      32(AX)(SI*8), X4
	VMOVUPD      48(AX)(SI*8), X5
	VMULPD       X1, X3, X6
	VFNMADD231PD X0, X5, X6
	VMULPD       X0, X3, X0
	VFMADD231PD  X1, X5, X0
	VADDPD       X6, X2, X1
	VSUBPD       X6, X2, X2
	VADDPD       X0, X4, X3
	VSUBPD       X0, X4, X0
	VMOVUPD      X1, (AX)(SI*8)
	VMOVUPD      X2, 16(AX)(SI*8)
	VMOVUPD      X3, 32(AX)(SI*8)
	VMOVUPD      X0, 48(AX)(SI*8)
	ADDQ         $0x08, SI

last_loop_2_end:
	CMPQ  SI, DX
	JL    last_loop_2_body
	VPXOR Y0, Y0, Y0
	XORQ  SI, SI
	JMP   last_loop_1_end

last_loop_1_body:
	VMOVUPD        (CX)(BX*8), Y1
	VSHUFPD        $0x05, Y1, Y1, Y2
	ADDQ           $0x04, BX
	VMOVUPD        (AX)(SI*8), Y3
	VMOVUPD        32(AX)(SI*8), Y4
	VSHUFPD        $0x0f, Y3, Y3, Y5
	VSHUFPD        $0x0f, Y4, Y4, Y6
	VMULPD         Y2, Y6, Y2
	VFMADDSUB231PD Y1, Y5, Y2
	VSHUFPD        $0x00, Y3, Y3, Y1
	VSHUFPD        $0x00, Y4, Y4, Y3
	VSHUFPD        $0x00, Y2, Y2, Y4
	VSHUFPD        $0x0f, Y2, Y2, Y2
	VSUBPD         Y4, Y0, Y4
	VSUBPD         Y2, Y0, Y2
	VADDSUBPD      Y4, Y1, Y1
	VADDSUBPD      Y2, Y3, Y2
	VMOVUPD        Y1, (AX)(SI*8)
	VMOVUPD        Y2, 32(AX)(SI*8)
	ADDQ           $0x08, SI

last_loop_1_end:
	CMPQ SI, DX
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
	VSHUFPD      $0x00, X0, X0, X1
	VSHUFPD      $0x03, X0, X0, X0
	ADDQ         $0x02, BX
	VMOVUPD      (AX)(SI*8), X2
	VMOVUPD      16(AX)(SI*8), X3
	VMOVUPD      32(AX)(SI*8), X4
	VMOVUPD      48(AX)(SI*8), X5
	VADDPD       X3, X2, X6
	VADDPD       X5, X4, X7
	VSUBPD       X3, X2, X2
	VSUBPD       X5, X4, X3
	VMULPD       X1, X2, X4
	VFNMADD231PD X0, X3, X4
	VMULPD       X0, X2, X0
	VFMADD231PD  X1, X3, X0
	VMOVUPD      X6, (AX)(SI*8)
	VMOVUPD      X4, 16(AX)(SI*8)
	VMOVUPD      X7, 32(AX)(SI*8)
	VMOVUPD      X0, 48(AX)(SI*8)
	ADDQ         $0x08, SI

first_loop_2_end:
	CMPQ SI, DX
	JL   first_loop_2_body
	MOVQ $0x0000000000000008, SI
	MOVQ DX, DI
	SHRQ $0x03, DI
	JMP  m_loop_end

m_loop_body:
	XORQ R8, R8
	MOVQ DI, R9
	SHRQ $0x01, R9
	XORQ R10, R10
	JMP  i_loop_end

i_loop_body:
	MOVQ         R8, R11
	ADDQ         SI, R11
	VBROADCASTSD (CX)(BX*8), Y0
	VBROADCASTSD 8(CX)(BX*8), Y1
	ADDQ         $0x02, BX
	MOVQ         R8, R12
	MOVQ         R11, R13
	JMP          j_loop_end

j_loop_body:
	VMOVUPD      (AX)(R12*8), Y2
	VMOVUPD      32(AX)(R12*8), Y3
	VMOVUPD      (AX)(R13*8), Y4
	VMOVUPD      32(AX)(R13*8), Y5
	VADDPD       Y4, Y2, Y6
	VADDPD       Y5, Y3, Y7
	VSUBPD       Y4, Y2, Y2
	VSUBPD       Y5, Y3, Y3
	VMULPD       Y0, Y2, Y4
	VFNMADD231PD Y1, Y3, Y4
	VMULPD       Y1, Y2, Y2
	VFMADD231PD  Y0, Y3, Y2
	VMOVUPD      Y6, (AX)(R12*8)
	VMOVUPD      Y7, 32(AX)(R12*8)
	VMOVUPD      Y4, (AX)(R13*8)
	VMOVUPD      Y2, 32(AX)(R13*8)
	ADDQ         $0x08, R12
	ADDQ         $0x08, R13

j_loop_end:
	CMPQ R12, R11
	JL   j_loop_body
	ADDQ SI, R8
	ADDQ SI, R8
	ADDQ $0x01, R10

i_loop_end:
	CMPQ R10, R9
	JL   i_loop_body
	SHLQ $0x01, SI
	SHRQ $0x01, DI

m_loop_end:
	CMPQ         DI, $0x02
	JG           m_loop_body
	VBROADCASTSD scale+48(FP), Y0
	VBROADCASTSD (CX)(BX*8), Y1
	VBROADCASTSD 8(CX)(BX*8), Y2
	MOVQ         DX, CX
	SHRQ         $0x01, CX
	XORQ         DX, DX
	MOVQ         CX, BX
	JMP          last_loop_end

last_loop_body:
	VMOVUPD      (AX)(DX*8), Y3
	VMOVUPD      32(AX)(DX*8), Y4
	VMOVUPD      (AX)(BX*8), Y5
	VMOVUPD      32(AX)(BX*8), Y6
	VADDPD       Y5, Y3, Y7
	VADDPD       Y6, Y4, Y8
	VSUBPD       Y5, Y3, Y3
	VSUBPD       Y6, Y4, Y4
	VMULPD       Y1, Y3, Y5
	VFNMADD231PD Y2, Y4, Y5
	VMULPD       Y2, Y3, Y3
	VFMADD231PD  Y1, Y4, Y3
	VMULPD       Y0, Y7, Y7
	VMULPD       Y0, Y8, Y8
	VMULPD       Y0, Y5, Y5
	VMULPD       Y0, Y3, Y3
	VMOVUPD      Y7, (AX)(DX*8)
	VMOVUPD      Y8, 32(AX)(DX*8)
	VMOVUPD      Y5, (AX)(BX*8)
	VMOVUPD      Y3, 32(AX)(BX*8)
	ADDQ         $0x08, DX
	ADDQ         $0x08, BX

last_loop_end:
	CMPQ DX, CX
	JL   last_loop_body
	RET

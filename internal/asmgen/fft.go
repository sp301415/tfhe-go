package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func fftInPlaceAVX2() {
	TEXT("fftInPlaceAVX2", NOSPLIT, "func(coeffs []float64, tw []complex128)")
	Pragma("noescape")

	coeffs := Load(Param("coeffs").Base(), GP64())
	tw := Load(Param("tw").Base(), GP64())
	N := Load(Param("coeffs").Len(), GP64())

	w := GP64()
	XORQ(w, w)

	// First Loop
	wReal, wImag := YMM(), YMM()
	VBROADCASTSD(Mem{Base: tw, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: tw, Index: w, Scale: 8, Disp: 8}, wImag)
	ADDQ(Imm(2), w)

	N_2 := GP64()
	MOVQ(N, N_2)
	SHRQ(Imm(1), N_2)

	j := GP64()
	XORQ(j, j)
	jj := GP64()
	MOVQ(N_2, jj)
	JMP(LabelRef("first_loop_end"))
	Label("first_loop_body")

	uReal, uImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32}, vImag)

	w_vReal := YMM()
	VMULPD(wReal, vReal, w_vReal)
	VFNMADD231PD(wImag, vImag, w_vReal)

	w_vImag := YMM()
	VMULPD(wImag, vReal, w_vImag)
	VFMADD231PD(wReal, vImag, w_vImag)

	uOutReal := YMM()
	VADDPD(w_vReal, uReal, uOutReal)
	uOutImag := YMM()
	VADDPD(w_vImag, uImag, uOutImag)

	vOutReal := YMM()
	VSUBPD(w_vReal, uReal, vOutReal)
	vOutImag := YMM()
	VSUBPD(w_vImag, uImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: jj, Scale: 8})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jj)

	Label("first_loop_end")
	CMPQ(j, N_2)
	JL(LabelRef("first_loop_body"))

	// Main Loop
	N_8 := GP64()
	MOVQ(N, N_8)
	SHRQ(Imm(3), N_8)

	t := GP64()
	MOVQ(N_2, t)
	m := GP64()
	MOVQ(U64(2), m)
	JMP(LabelRef("main_loop_end"))
	Label("main_loop_body")

	SHRQ(Imm(1), t)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("i_loop_end"))
	Label("i_loop_body")

	j1 := GP64()
	MOVQ(t, j1)
	IMULQ(i, j1)
	SHLQ(Imm(1), j1)
	j2 := GP64()
	MOVQ(j1, j2)
	ADDQ(t, j2)

	wReal, wImag = YMM(), YMM()
	VBROADCASTSD(Mem{Base: tw, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: tw, Index: w, Scale: 8, Disp: 8}, wImag)
	ADDQ(Imm(2), w)

	j, jj = GP64(), GP64()
	MOVQ(j1, j)
	MOVQ(j2, jj)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop_body")

	uReal, uImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32}, vImag)

	w_vReal = YMM()
	VMULPD(wReal, vReal, w_vReal)
	VFNMADD231PD(wImag, vImag, w_vReal)

	w_vImag = YMM()
	VMULPD(wImag, vReal, w_vImag)
	VFMADD231PD(wReal, vImag, w_vImag)

	uOutReal = YMM()
	VADDPD(w_vReal, uReal, uOutReal)
	uOutImag = YMM()
	VADDPD(w_vImag, uImag, uOutImag)

	vOutReal = YMM()
	VSUBPD(w_vReal, uReal, vOutReal)
	vOutImag = YMM()
	VSUBPD(w_vImag, uImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: jj, Scale: 8})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jj)

	Label("j_loop_end")
	CMPQ(j, j2)
	JL(LabelRef("j_loop_body"))

	ADDQ(Imm(1), i)

	Label("i_loop_end")
	CMPQ(i, m)
	JL(LabelRef("i_loop_body"))

	SHLQ(Imm(1), m)

	Label("main_loop_end")
	CMPQ(m, N_8)
	JL(LabelRef("main_loop_body"))

	// Stride 2
	j = GP64()
	XORQ(j, j)
	JMP(LabelRef("last_loop_2_end"))
	Label("last_loop_2_body")

	w_X, wReal_X, wImag_X := XMM(), XMM(), XMM()
	VMOVUPD(Mem{Base: tw, Index: w, Scale: 8}, w_X)
	VSHUFPD(Imm(0b00), w_X, w_X, wReal_X)
	VSHUFPD(Imm(0b11), w_X, w_X, wImag_X)
	ADDQ(Imm(2), w)

	uReal_X, vReal_X := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal_X)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16}, vReal_X)
	uImag_X, vImag_X := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag_X)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48}, vImag_X)

	w_vReal_X := XMM()
	VMULPD(wReal_X, vReal_X, w_vReal_X)
	VFNMADD231PD(wImag_X, vImag_X, w_vReal_X)
	w_vImag_X := XMM()
	VMULPD(wImag_X, vReal_X, w_vImag_X)
	VFMADD231PD(wReal_X, vImag_X, w_vImag_X)

	uOutReal_X := XMM()
	VADDPD(w_vReal_X, uReal_X, uOutReal_X)
	vOutReal_X := XMM()
	VSUBPD(w_vReal_X, uReal_X, vOutReal_X)

	uOutImag_X := XMM()
	VADDPD(w_vImag_X, uImag_X, uOutImag_X)
	vOutImag_X := XMM()
	VSUBPD(w_vImag_X, uImag_X, vOutImag_X)

	VMOVUPD(uOutReal_X, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOutReal_X, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16})
	VMOVUPD(uOutImag_X, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutImag_X, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48})

	ADDQ(Imm(8), j)

	Label("last_loop_2_end")
	CMPQ(j, N)
	JL(LabelRef("last_loop_2_body"))

	// Stride 1
	zero := YMM()
	VPXOR(zero, zero, zero)

	j = GP64()
	XORQ(j, j)
	JMP(LabelRef("last_loop_1_end"))
	Label("last_loop_1_body")

	// wRealImag: (w0Real, w0Imag, w1Real, w1Imag)
	// wImagReal: (w0Imag, w0Real, w1Imag, w1Real)
	wRealImag, wImagReal := YMM(), YMM()
	VMOVUPD(Mem{Base: tw, Index: w, Scale: 8}, wRealImag)
	VSHUFPD(Imm(0b0101), wRealImag, wRealImag, wImagReal)
	ADDQ(Imm(4), w)

	// uRealvReal: (u0Real, v0Real, u1Real, v1Real)
	// uImagvImag: (u0Imag, v0Imag, u1Imag, v1Imag)
	uRealvReal, uImagvImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uRealvReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImagvImag)

	// vReal: (v0Real, v0Real, v1Real, v1Real)
	// vImag: (v0Imag, v0Imag, v1Imag, v1Imag)
	vReal, vImag = YMM(), YMM()
	VSHUFPD(Imm(0b1111), uRealvReal, uRealvReal, vReal)
	VSHUFPD(Imm(0b1111), uImagvImag, uImagvImag, vImag)

	// w_vRealImag: ((v0 * w0)Real, (v0 * w0)Imag, (v1 * w1)Real, (v1 * w1)Imag)
	w_vRealImag := YMM()
	VMULPD(wImagReal, vImag, w_vRealImag)
	VFMADDSUB231PD(wRealImag, vReal, w_vRealImag)

	// uReal: (u0Real, u0Real, u1Real, u1Real)
	// uImag: (u0Imag, u0Imag, u1Imag, u1Imag)
	uReal, uImag = YMM(), YMM()
	VSHUFPD(Imm(0b0000), uRealvReal, uRealvReal, uReal)
	VSHUFPD(Imm(0b0000), uImagvImag, uImagvImag, uImag)

	// w_vReal: (v0 * w0)Real, (v0 * w0)Real, (v1 * w1)Real, (v1 * w1)Real
	// w_vImag: (v0 * w0)Imag, (v0 * w0)Imag, (v1 * w1)Imag, (v1 * w1)Imag
	w_vReal, w_vImag = YMM(), YMM()
	VSHUFPD(Imm(0b0000), w_vRealImag, w_vRealImag, w_vReal)
	VSHUFPD(Imm(0b1111), w_vRealImag, w_vRealImag, w_vImag)
	VSUBPD(w_vReal, zero, w_vReal)
	VSUBPD(w_vImag, zero, w_vImag)

	// uOut: (u0Real + (v0 * w0)Real, u0Real - (v0 * w0)Real, u1Real + (v1 * w1)Real, u1Real - (v1 * w1)Real)
	// vOut: (u0Imag + (v0 * w0)Imag, u0Imag - (v0 * w0)Imag, u1Imag + (v1 * w1)Imag, u1Imag - (v1 * w1)Imag)
	uOut, vOut := YMM(), YMM()
	VADDSUBPD(w_vReal, uReal, uOut)
	VADDSUBPD(w_vImag, uImag, vOut)

	VMOVUPD(uOut, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOut, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)

	Label("last_loop_1_end")
	CMPQ(j, N)
	JL(LabelRef("last_loop_1_body"))

	RET()
}

func invFFTInPlaceAVX2() {
	TEXT("invFFTInPlaceAVX2", NOSPLIT, "func(coeffs []float64, twInv []complex128, scale float64)")
	Pragma("noescape")

	coeffs := Load(Param("coeffs").Base(), GP64())
	twInv := Load(Param("twInv").Base(), GP64())
	N := Load(Param("coeffs").Len(), GP64())

	w := GP64()
	XORQ(w, w)

	// Stride 1
	j := GP64()
	XORQ(j, j)
	JMP(LabelRef("first_loop_1_end"))
	Label("first_loop_1_body")

	// wRealImag: (w0Real, w0Imag, w1Real, w1Imag)
	// wImagReal: (w0Imag, w0Real, w1Imag, w1Real)
	wRealImag, wImagReal := YMM(), YMM()
	VMOVUPD(Mem{Base: twInv, Index: w, Scale: 8}, wRealImag)
	VSHUFPD(Imm(0b0101), wRealImag, wRealImag, wImagReal)
	ADDQ(Imm(4), w)

	// uRealvReal: (u0Real, v0Real, u1Real, v1Real)
	// uImagvImag: (u0Imag, v0Imag, u1Imag, v1Imag)
	uRealvReal, uImagvImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uRealvReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImagvImag)

	// uOutReal: (u0Real + v0Real, u0Real + v0Real, u1Real + v1Real, u1Real + v1Real)
	// uOutImag: (u0Imag + v0Imag, u0Imag + v0Imag, u1Imag + v1Imag, u1Imag + v1Imag)
	uOutReal, uOutImag := YMM(), YMM()
	VHADDPD(uRealvReal, uRealvReal, uOutReal)
	VHADDPD(uImagvImag, uImagvImag, uOutImag)

	// uRealImag: (u0Real, u0Imag, u1Real, u1Imag)
	// vRealImag: (v0Real, v0Imag, v1Real, v1Imag)
	uRealImag, vRealImag := YMM(), YMM()
	VSHUFPD(Imm(0b0000), uImagvImag, uRealvReal, uRealImag)
	VSHUFPD(Imm(0b1111), uImagvImag, uRealvReal, vRealImag)

	// u_vRealImag: (u0Real - v0Real, u0Imag - v0Imag, u1Real - v1Real, u1Imag - v1Imag)
	u_vRealImag := YMM()
	VSUBPD(vRealImag, uRealImag, u_vRealImag)

	// u_vReal: (u0Real - v0Real, u0Real - v0Real, u1Real - v1Real, u1Real - v1Real)
	// u_vImag: (u0Imag - v0Imag, u0Imag - v0Imag, u1Imag - v1Imag, u1Imag - v1Imag)
	u_vReal, u_vImag := YMM(), YMM()
	VSHUFPD(Imm(0b0000), u_vRealImag, u_vRealImag, u_vReal)
	VSHUFPD(Imm(0b1111), u_vRealImag, u_vRealImag, u_vImag)

	// vOutRealImag: ((u0 - v0) * w0)Real, ((u0 - v0) * w0)Imag, ((u1 - v1) * w1)Real, ((u1 - v1) * w1)Imag
	vOutRealImag := YMM()
	VMULPD(wImagReal, u_vImag, vOutRealImag)
	VFMADDSUB231PD(wRealImag, u_vReal, vOutRealImag)

	// uOut: ((u0 + v0)Real, ((u0 - v0) * w0)Real, (u1 + v1)Real, ((u1 - v1) * w1)Real)
	// vOut: ((u0 + v0)Imag, ((u0 - v0) * w0)Imag, (u1 + v1)Imag, ((u1 - v1) * w1)Imag)
	uOut, vOut := YMM(), YMM()
	VSHUFPD(Imm(0b0000), vOutRealImag, uOutReal, uOut)
	VSHUFPD(Imm(0b1111), vOutRealImag, uOutImag, vOut)

	VMOVUPD(uOut, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOut, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)

	Label("first_loop_1_end")
	CMPQ(j, N)
	JL(LabelRef("first_loop_1_body"))

	// Stride 2
	j = GP64()
	XORQ(j, j)
	JMP(LabelRef("first_loop_2_end"))
	Label("first_loop_2_body")

	w_X, wReal_X, wImag_X := XMM(), XMM(), XMM()
	VMOVUPD(Mem{Base: twInv, Index: w, Scale: 8}, w_X)
	VSHUFPD(Imm(0b00), w_X, w_X, wReal_X)
	VSHUFPD(Imm(0b11), w_X, w_X, wImag_X)
	ADDQ(Imm(2), w)

	uReal_X, vReal_X := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal_X)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16}, vReal_X)
	uImag_X, vImag_X := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag_X)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48}, vImag_X)

	uOutReal_X, uOutImag_X := XMM(), XMM()
	VADDPD(vReal_X, uReal_X, uOutReal_X)
	VADDPD(vImag_X, uImag_X, uOutImag_X)

	u_vReal_X, u_vImag_X := XMM(), XMM()
	VSUBPD(vReal_X, uReal_X, u_vReal_X)
	VSUBPD(vImag_X, uImag_X, u_vImag_X)

	vOutReal_X := XMM()
	VMULPD(wReal_X, u_vReal_X, vOutReal_X)
	VFNMADD231PD(wImag_X, u_vImag_X, vOutReal_X)
	vOutImag_X := XMM()
	VMULPD(wImag_X, u_vReal_X, vOutImag_X)
	VFMADD231PD(wReal_X, u_vImag_X, vOutImag_X)

	VMOVUPD(uOutReal_X, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOutReal_X, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16})
	VMOVUPD(uOutImag_X, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutImag_X, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48})

	ADDQ(Imm(8), j)

	Label("first_loop_2_end")
	CMPQ(j, N)
	JL(LabelRef("first_loop_2_body"))

	// Main Loop
	t := GP64()
	MOVQ(U64(8), t)

	m := GP64()
	MOVQ(N, m)
	SHRQ(Imm(3), m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop_body")

	j1 := GP64()
	XORQ(j1, j1)

	h := GP64()
	MOVQ(m, h)
	SHRQ(Imm(1), h)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("i_loop_end"))
	Label("i_loop_body")

	j2 := GP64()
	MOVQ(j1, j2)
	ADDQ(t, j2)

	wReal, wImag := YMM(), YMM()
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8, Disp: 8}, wImag)
	ADDQ(Imm(2), w)

	j, jj := GP64(), GP64()
	MOVQ(j1, j)
	MOVQ(j2, jj)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop_body")

	uReal, uImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32}, vImag)

	uOutReal, uOutImag = YMM(), YMM()
	VADDPD(vReal, uReal, uOutReal)
	VADDPD(vImag, uImag, uOutImag)

	u_vReal, u_vImag = YMM(), YMM()
	VSUBPD(vReal, uReal, u_vReal)
	VSUBPD(vImag, uImag, u_vImag)

	vOutReal := YMM()
	VMULPD(wReal, u_vReal, vOutReal)
	VFNMADD231PD(wImag, u_vImag, vOutReal)
	vOutImag := YMM()
	VMULPD(wImag, u_vReal, vOutImag)
	VFMADD231PD(wReal, u_vImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: jj, Scale: 8})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jj)

	Label("j_loop_end")
	CMPQ(j, j2)
	JL(LabelRef("j_loop_body"))

	ADDQ(t, j1)
	ADDQ(t, j1)
	ADDQ(Imm(1), i)

	Label("i_loop_end")
	CMPQ(i, h)
	JL(LabelRef("i_loop_body"))

	SHLQ(Imm(1), t)
	SHRQ(Imm(1), m)

	Label("m_loop_end")
	CMPQ(m, Imm(2))
	JG(LabelRef("m_loop_body"))

	// Last Loop
	scale := YMM()
	VBROADCASTSD(NewParamAddr("scale", 48), scale)

	wReal, wImag = YMM(), YMM()
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8, Disp: 8}, wImag)

	N_2 := GP64()
	MOVQ(N, N_2)
	SHRQ(Imm(1), N_2)

	j, jj = GP64(), GP64()
	XORQ(j, j)
	MOVQ(N_2, jj)
	JMP(LabelRef("last_loop_end"))
	Label("last_loop_body")

	uReal, uImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32}, vImag)

	uOutReal, uOutImag = YMM(), YMM()
	VADDPD(vReal, uReal, uOutReal)
	VADDPD(vImag, uImag, uOutImag)

	u_vReal, u_vImag = YMM(), YMM()
	VSUBPD(vReal, uReal, u_vReal)
	VSUBPD(vImag, uImag, u_vImag)

	vOutReal = YMM()
	VMULPD(wReal, u_vReal, vOutReal)
	VFNMADD231PD(wImag, u_vImag, vOutReal)
	vOutImag = YMM()
	VMULPD(wImag, u_vReal, vOutImag)
	VFMADD231PD(wReal, u_vImag, vOutImag)

	VMULPD(scale, uOutReal, uOutReal)
	VMULPD(scale, uOutImag, uOutImag)
	VMULPD(scale, vOutReal, vOutReal)
	VMULPD(scale, vOutImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: jj, Scale: 8})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: jj, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jj)

	Label("last_loop_end")
	CMPQ(j, N_2)
	JL(LabelRef("last_loop_body"))

	RET()
}

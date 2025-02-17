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

	wReal, wImag := YMM(), YMM()
	VBROADCASTSD(Mem{Base: tw, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: tw, Index: w, Scale: 8, Disp: 8}, wImag)
	ADDQ(Imm(2), w)

	NDiv2 := GP64()
	MOVQ(N, NDiv2)
	SHRQ(Imm(1), NDiv2)

	j := GP64()
	XORQ(j, j)
	jt := GP64()
	MOVQ(NDiv2, jt)
	JMP(LabelRef("first_loop_end"))
	Label("first_loop_body")

	uReal, uImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vImag)

	vwReal := YMM()
	VMULPD(wReal, vReal, vwReal)
	VFNMADD231PD(wImag, vImag, vwReal)

	vwImag := YMM()
	VMULPD(wImag, vReal, vwImag)
	VFMADD231PD(wReal, vImag, vwImag)

	uOutReal := YMM()
	VADDPD(vwReal, uReal, uOutReal)
	uOutImag := YMM()
	VADDPD(vwImag, uImag, uOutImag)

	vOutReal := YMM()
	VSUBPD(vwReal, uReal, vOutReal)
	vOutImag := YMM()
	VSUBPD(vwImag, uImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jt)

	Label("first_loop_end")
	CMPQ(j, NDiv2)
	JL(LabelRef("first_loop_body"))

	NDiv16 := GP64()
	MOVQ(N, NDiv16)
	SHRQ(Imm(4), NDiv16)

	t := GP64()
	MOVQ(NDiv2, t)
	m := GP64()
	MOVQ(U64(2), m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop_body")

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

	j, jt = GP64(), GP64()
	MOVQ(j1, j)
	MOVQ(j2, jt)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop_body")

	uReal, uImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vImag)

	vwReal = YMM()
	VMULPD(wReal, vReal, vwReal)
	VFNMADD231PD(wImag, vImag, vwReal)

	vwImag = YMM()
	VMULPD(wImag, vReal, vwImag)
	VFMADD231PD(wReal, vImag, vwImag)

	uOutReal = YMM()
	VADDPD(vwReal, uReal, uOutReal)
	uOutImag = YMM()
	VADDPD(vwImag, uImag, uOutImag)

	vOutReal = YMM()
	VSUBPD(vwReal, uReal, vOutReal)
	vOutImag = YMM()
	VSUBPD(vwImag, uImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jt)

	Label("j_loop_end")
	CMPQ(j, j2)
	JL(LabelRef("j_loop_body"))

	ADDQ(Imm(1), i)

	Label("i_loop_end")
	CMPQ(i, m)
	JL(LabelRef("i_loop_body"))

	SHLQ(Imm(1), m)

	Label("m_loop_end")
	CMPQ(m, NDiv16)
	JLE(LabelRef("m_loop_body"))

	j = GP64()
	XORQ(j, j)
	JMP(LabelRef("last_loop_2_end"))
	Label("last_loop_2_body")

	wReal, wImag = XMM(), XMM()
	VMOVUPD(Mem{Base: tw, Index: w, Scale: 8}, wReal)
	VSHUFPD(Imm(0b11), wReal, wReal, wImag)
	VSHUFPD(Imm(0b00), wReal, wReal, wReal)
	ADDQ(Imm(2), w)

	uReal, vReal = XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16}, vReal)
	uImag, vImag = XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48}, vImag)

	vwReal = XMM()
	VMULPD(wReal, vReal, vwReal)
	VFNMADD231PD(wImag, vImag, vwReal)

	vwImag = XMM()
	VMULPD(wImag, vReal, vwImag)
	VFMADD231PD(wReal, vImag, vwImag)

	uOutReal, vOutReal = XMM(), XMM()
	VADDPD(vwReal, uReal, uOutReal)
	VSUBPD(vwReal, uReal, vOutReal)

	uOutImag, vOutImag = XMM(), XMM()
	VADDPD(vwImag, uImag, uOutImag)
	VSUBPD(vwImag, uImag, vOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOutReal, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48})

	ADDQ(Imm(8), j)

	Label("last_loop_2_end")
	CMPQ(j, N)
	JL(LabelRef("last_loop_2_body"))

	zero := YMM()
	VPXOR(zero, zero, zero)

	j = GP64()
	XORQ(j, j)
	JMP(LabelRef("last_loop_1_end"))
	Label("last_loop_1_body")

	// wRealImag: (wReal0, wImag0, wReal1, wImag1)
	// wImagReal: (wImag0, wReal0, wImag1, wReal1)
	wRealImag, wImagReal := YMM(), YMM()
	VMOVUPD(Mem{Base: tw, Index: w, Scale: 8}, wRealImag)
	VSHUFPD(Imm(0b0101), wRealImag, wRealImag, wImagReal)
	ADDQ(Imm(4), w)

	// uRealvReal: (uReal0, vReal0, uReal1, vReal1)
	// uImagvImag: (uImag0, vImag0, uImag1, vImag1)
	uRealvReal, uImagvImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uRealvReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImagvImag)

	// vReal: (vReal0, vReal0, vReal0, vReal0)
	// vImag: (vImag0, vImag0, vImag0, vImag0)
	vReal, vImag = YMM(), YMM()
	VSHUFPD(Imm(0b1111), uRealvReal, uRealvReal, vReal)
	VSHUFPD(Imm(0b1111), uImagvImag, uImagvImag, vImag)

	// vwRealImag: (vwReal0, vwImag0, vwReal1, vwImag1)
	vwRealImag := YMM()
	VMULPD(wImagReal, vImag, vwRealImag)
	VFMADDSUB231PD(wRealImag, vReal, vwRealImag)

	// uReal: (uReal0, uReal0, uReal1, uReal1)
	// uImag: (uImag0, uImag0, uImag1, uImag1)
	uReal, uImag = YMM(), YMM()
	VSHUFPD(Imm(0b0000), uRealvReal, uRealvReal, uReal)
	VSHUFPD(Imm(0b0000), uImagvImag, uImagvImag, uImag)

	// vwReal: (vwReal0, vwReal0, vwReal1, vwReal1)
	// vwImag: (vwImag0, vwImag0, vwImag1, vwImag1)
	vwReal, vwImag = YMM(), YMM()
	VSHUFPD(Imm(0b0000), vwRealImag, vwRealImag, vwReal)
	VSHUFPD(Imm(0b1111), vwRealImag, vwRealImag, vwImag)

	VSUBPD(vwReal, zero, vwReal)
	VSUBPD(vwImag, zero, vwImag)

	uOut, vOut := YMM(), YMM()
	VADDSUBPD(vwReal, uReal, uOut)
	VADDSUBPD(vwImag, uImag, vOut)

	VMOVUPD(uOut, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOut, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)

	Label("last_loop_1_end")
	CMPQ(j, N)
	JL(LabelRef("last_loop_1_body"))

	RET()
}

func ifftInPlaceAVX2() {
	TEXT("ifftInPlaceAVX2", NOSPLIT, "func(coeffs []float64, twInv []complex128, scale float64)")
	Pragma("noescape")

	coeffs := Load(Param("coeffs").Base(), GP64())
	twInv := Load(Param("twInv").Base(), GP64())
	N := Load(Param("coeffs").Len(), GP64())

	w := GP64()
	XORQ(w, w)

	j := GP64()
	XORQ(j, j)
	JMP(LabelRef("first_loop_1_end"))
	Label("first_loop_1_body")

	// wRealImag: (wReal0, wImag0, wReal1, wImag1)
	// wImagReal: (wImag0, wReal0, wImag1, wReal1)
	wRealImag, wImagReal := YMM(), YMM()
	VMOVUPD(Mem{Base: twInv, Index: w, Scale: 8}, wRealImag)
	VSHUFPD(Imm(0b0101), wRealImag, wRealImag, wImagReal)
	ADDQ(Imm(4), w)

	// uRealvReal: (uReal0, vReal0, uReal0, vReal1)
	// uImagvImag: (uImag0, vImag0, uImag0, vImag1)
	uRealvReal, uImagvImag := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uRealvReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImagvImag)

	// uOutReal: (uOutReal0, uOutReal0, uOutReal1, uOutReal1)
	// uOutImag: (uOutImag0, uOutImag0, uOutImag1, uOutImag1)
	uOutReal, uOutImag := YMM(), YMM()
	VHADDPD(uRealvReal, uRealvReal, uOutReal)
	VHADDPD(uImagvImag, uImagvImag, uOutImag)

	// uRealImag: (u0Real, u0Imag, u1Real, u1Imag)
	// vRealImag: (v0Real, v0Imag, v1Real, v1Imag)
	uRealImag, vRealImag := YMM(), YMM()
	VSHUFPD(Imm(0b0000), uImagvImag, uRealvReal, uRealImag)
	VSHUFPD(Imm(0b1111), uImagvImag, uRealvReal, vRealImag)

	// vOutRealImag: (vOutReal0, vOutImag0, vOutReal1, vOutImag1)
	vOutRealImag := YMM()
	VSUBPD(vRealImag, uRealImag, vOutRealImag)

	// vOutReal: (vOutReal0, vOutReal0, vOutReal1, vOutReal1)
	// vOutImag: (vOutImag0, vOutImag0, vOutImag1, vOutImag1)
	vOutReal, vOutImag := YMM(), YMM()
	VSHUFPD(Imm(0b0000), vOutRealImag, vOutRealImag, vOutReal)
	VSHUFPD(Imm(0b1111), vOutRealImag, vOutRealImag, vOutImag)

	// vwOutRealImag: (vwOutReal0, vwOutImag0, vwOutReal1, vwOutImag1)
	vwOutRealImag := YMM()
	VMULPD(wImagReal, vOutImag, vwOutRealImag)
	VFMADDSUB231PD(wRealImag, vOutReal, vwOutRealImag)

	uOut, vOut := YMM(), YMM()
	VSHUFPD(Imm(0b0000), vwOutRealImag, uOutReal, uOut)
	VSHUFPD(Imm(0b1111), vwOutRealImag, uOutImag, vOut)

	VMOVUPD(uOut, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOut, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)

	Label("first_loop_1_end")
	CMPQ(j, N)
	JL(LabelRef("first_loop_1_body"))

	j = GP64()
	XORQ(j, j)
	JMP(LabelRef("first_loop_2_end"))
	Label("first_loop_2_body")

	wReal, wImag := XMM(), XMM()
	VMOVUPD(Mem{Base: twInv, Index: w, Scale: 8}, wReal)
	VSHUFPD(Imm(0b11), wReal, wReal, wImag)
	VSHUFPD(Imm(0b00), wReal, wReal, wReal)
	ADDQ(Imm(2), w)

	uReal, vReal := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16}, vReal)
	uImag, vImag := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48}, vImag)

	uOutReal, uOutImag = XMM(), XMM()
	VADDPD(vReal, uReal, uOutReal)
	VADDPD(vImag, uImag, uOutImag)

	vOutReal, vOutImag = XMM(), XMM()
	VSUBPD(vReal, uReal, vOutReal)
	VSUBPD(vImag, uImag, vOutImag)

	vwOutReal := XMM()
	VMULPD(wReal, vOutReal, vwOutReal)
	VFNMADD231PD(wImag, vOutImag, vwOutReal)

	vwOutImag := XMM()
	VMULPD(wImag, vOutReal, vwOutImag)
	VFMADD231PD(wReal, vOutImag, vwOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vwOutReal, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vwOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48})

	ADDQ(Imm(8), j)

	Label("first_loop_2_end")
	CMPQ(j, N)
	JL(LabelRef("first_loop_2_body"))

	t := GP64()
	MOVQ(U64(8), t)

	m := GP64()
	MOVQ(N, m)
	SHRQ(Imm(4), m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop_body")

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
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8, Disp: 8}, wImag)
	ADDQ(Imm(2), w)

	j, jt := GP64(), GP64()
	MOVQ(j1, j)
	MOVQ(j2, jt)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop_body")

	uReal, uImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vImag)

	uOutReal, uOutImag = YMM(), YMM()
	VADDPD(vReal, uReal, uOutReal)
	VADDPD(vImag, uImag, uOutImag)

	vOutReal, vOutImag = YMM(), YMM()
	VSUBPD(vReal, uReal, vOutReal)
	VSUBPD(vImag, uImag, vOutImag)

	vwOutReal = YMM()
	VMULPD(wReal, vOutReal, vwOutReal)
	VFNMADD231PD(wImag, vOutImag, vwOutReal)

	vwOutImag = YMM()
	VMULPD(wImag, vOutReal, vwOutImag)
	VFMADD231PD(wReal, vOutImag, vwOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vwOutReal, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vwOutImag, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jt)

	Label("j_loop_end")
	CMPQ(j, j2)
	JL(LabelRef("j_loop_body"))

	ADDQ(Imm(1), i)

	Label("i_loop_end")
	CMPQ(i, m)
	JL(LabelRef("i_loop_body"))

	SHLQ(Imm(1), t)
	SHRQ(Imm(1), m)

	Label("m_loop_end")
	CMPQ(m, Imm(2))
	JGE(LabelRef("m_loop_body"))

	scale := YMM()
	VBROADCASTSD(NewParamAddr("scale", 48), scale)

	wReal, wImag = YMM(), YMM()
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8}, wReal)
	VBROADCASTSD(Mem{Base: twInv, Index: w, Scale: 8, Disp: 8}, wImag)

	NDiv2 := GP64()
	MOVQ(N, NDiv2)
	SHRQ(Imm(1), NDiv2)

	j, jt = GP64(), GP64()
	XORQ(j, j)
	MOVQ(NDiv2, jt)
	JMP(LabelRef("last_loop_end"))
	Label("last_loop_body")

	uReal, uImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uReal)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uImag)
	vReal, vImag = YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vReal)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vImag)

	uOutReal, uOutImag = YMM(), YMM()
	VADDPD(vReal, uReal, uOutReal)
	VADDPD(vImag, uImag, uOutImag)

	vOutReal, vOutImag = YMM(), YMM()
	VSUBPD(vReal, uReal, vOutReal)
	VSUBPD(vImag, uImag, vOutImag)

	vwOutReal = YMM()
	VMULPD(wReal, vOutReal, vwOutReal)
	VFNMADD231PD(wImag, vOutImag, vwOutReal)

	vwOutImag = YMM()
	VMULPD(wImag, vOutReal, vwOutImag)
	VFMADD231PD(wReal, vOutImag, vwOutImag)

	VMULPD(scale, uOutReal, uOutReal)
	VMULPD(scale, uOutImag, uOutImag)
	VMULPD(scale, vwOutReal, vwOutReal)
	VMULPD(scale, vwOutImag, vwOutImag)

	VMOVUPD(uOutReal, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uOutImag, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vwOutReal, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vwOutImag, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jt)

	Label("last_loop_end")
	CMPQ(j, NDiv2)
	JL(LabelRef("last_loop_body"))

	RET()
}

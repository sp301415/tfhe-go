package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func FwdFFTInPlaceAVX2() {
	TEXT("fwdFFTInPlaceAVX2", NOSPLIT, "func(coeffs []float64, tw []complex128)")
	Pragma("noescape")

	coeffs := Load(Param("coeffs").Base(), GP64())
	tw := Load(Param("tw").Base(), GP64())
	N := Load(Param("coeffs").Len(), GP64())

	wIdx := GP64()
	XORQ(wIdx, wIdx)

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(1), M)

	wR, wI := YMM(), YMM()
	VBROADCASTSD(Mem{Base: tw, Index: wIdx, Scale: 8}, wR)
	VBROADCASTSD(Mem{Base: tw, Index: wIdx, Scale: 8, Disp: 8}, wI)
	ADDQ(Imm(2), wIdx)

	j, jt := GP64(), GP64()
	XORQ(j, j)
	MOVQ(M, jt)
	JMP(LabelRef("first_loop_end"))
	Label("first_loop_body")

	uR, uI := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uR)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uI)
	vR, vI := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vR)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vI)

	FwdButterflyAVX2(uR, uI, vR, vI, wR, wI)

	VMOVUPD(uR, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uI, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vR, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vI, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jt)

	Label("first_loop_end")
	CMPQ(j, M)
	JL(LabelRef("first_loop_body"))

	MOVQ(N, M)
	SHRQ(Imm(4), M)

	t, m := GP64(), GP64()
	MOVQ(N, t)
	SHRQ(Imm(1), t)
	MOVQ(U64(2), m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop_body")

	SHRQ(Imm(1), t)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("i_loop_end"))
	Label("i_loop_body")

	j1, j2 := GP64(), GP64()
	MOVQ(t, j1)
	IMULQ(i, j1)
	SHLQ(Imm(1), j1)
	MOVQ(j1, j2)
	ADDQ(t, j2)

	VBROADCASTSD(Mem{Base: tw, Index: wIdx, Scale: 8}, wR)
	VBROADCASTSD(Mem{Base: tw, Index: wIdx, Scale: 8, Disp: 8}, wI)
	ADDQ(Imm(2), wIdx)

	MOVQ(j1, j)
	MOVQ(j2, jt)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop_body")

	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uR)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uI)

	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vR)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vI)

	FwdButterflyAVX2(uR, uI, vR, vI, wR, wI)

	VMOVUPD(uR, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uI, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	VMOVUPD(vR, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vI, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

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
	CMPQ(m, M)
	JLE(LabelRef("m_loop_body"))

	XORQ(j, j)
	JMP(LabelRef("last_loop_2_end"))
	Label("last_loop_2_body")

	wReal128, wImag128 := XMM(), XMM()
	VMOVUPD(Mem{Base: tw, Index: wIdx, Scale: 8}, wReal128)
	VSHUFPD(Imm(0b11), wReal128, wReal128, wImag128)
	VSHUFPD(Imm(0b00), wReal128, wReal128, wReal128)
	ADDQ(Imm(2), wIdx)

	uR128, vR128 := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uR128)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16}, vR128)
	uI128, vI128 := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uI128)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48}, vI128)

	FwdButterflyAVX2XMM(uR128, uI128, vR128, vI128, wReal128, wImag128)

	VMOVUPD(uR128, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vR128, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16})
	VMOVUPD(uI128, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vI128, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48})

	ADDQ(Imm(8), j)

	Label("last_loop_2_end")
	CMPQ(j, N)
	JL(LabelRef("last_loop_2_body"))

	zero := YMM()
	VXORPD(zero, zero, zero)

	XORQ(j, j)
	JMP(LabelRef("last_loop_1_end"))
	Label("last_loop_1_body")

	wRI, wIR := YMM(), YMM()
	VMOVUPD(Mem{Base: tw, Index: wIdx, Scale: 8}, wRI)
	VSHUFPD(Imm(0b0101), wRI, wRI, wIR)
	ADDQ(Imm(4), wIdx)

	uRvR, uIvI := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uRvR)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uIvI)

	VSHUFPD(Imm(0b1111), uRvR, uRvR, vR)
	VSHUFPD(Imm(0b1111), uIvI, uIvI, vI)

	vwRI := YMM()
	VMULPD(wIR, vI, vwRI)
	VFMADDSUB231PD(wRI, vR, vwRI)

	VSHUFPD(Imm(0b0000), uRvR, uRvR, uR)
	VSHUFPD(Imm(0b0000), uIvI, uIvI, uI)

	vwR, vwI := YMM(), YMM()
	VSHUFPD(Imm(0b0000), vwRI, vwRI, vwR)
	VSHUFPD(Imm(0b1111), vwRI, vwRI, vwI)

	VSUBPD(vwR, zero, vwR)
	VSUBPD(vwI, zero, vwI)

	uOut, vOut := YMM(), YMM()
	VADDSUBPD(vwR, uR, uOut)
	VADDSUBPD(vwI, uI, vOut)

	VMOVUPD(uOut, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOut, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)

	Label("last_loop_1_end")
	CMPQ(j, N)
	JL(LabelRef("last_loop_1_body"))

	RET()
}

func InvFFTInPlaceAVX2() {
	TEXT("invFFTInPlaceAVX2", NOSPLIT, "func(coeffs []float64, twInv []complex128, scale float64)")
	Pragma("noescape")

	coeffs := Load(Param("coeffs").Base(), GP64())
	twInv := Load(Param("twInv").Base(), GP64())
	N := Load(Param("coeffs").Len(), GP64())

	wIdx := GP64()
	XORQ(wIdx, wIdx)

	j := GP64()
	XORQ(j, j)
	JMP(LabelRef("first_loop_1_end"))
	Label("first_loop_1_body")

	wRI, wIR := YMM(), YMM()
	VMOVUPD(Mem{Base: twInv, Index: wIdx, Scale: 8}, wRI)
	VSHUFPD(Imm(0b0101), wRI, wRI, wIR)
	ADDQ(Imm(4), wIdx)

	uRvR, uIvI := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uRvR)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uIvI)

	uOutR, uOutI := YMM(), YMM()
	VHADDPD(uRvR, uRvR, uOutR)
	VHADDPD(uIvI, uIvI, uOutI)

	uRI, vRI := YMM(), YMM()
	VSHUFPD(Imm(0b0000), uIvI, uRvR, uRI)
	VSHUFPD(Imm(0b1111), uIvI, uRvR, vRI)

	vOutRI := YMM()
	VSUBPD(vRI, uRI, vOutRI)

	vOutR, vOutI := YMM(), YMM()
	VSHUFPD(Imm(0b0000), vOutRI, vOutRI, vOutR)
	VSHUFPD(Imm(0b1111), vOutRI, vOutRI, vOutI)

	vwOutRI := YMM()
	VMULPD(wIR, vOutI, vwOutRI)
	VFMADDSUB231PD(wRI, vOutR, vwOutRI)

	uOut, vOut := YMM(), YMM()
	VSHUFPD(Imm(0b0000), vwOutRI, uOutR, uOut)
	VSHUFPD(Imm(0b1111), vwOutRI, uOutI, vOut)

	VMOVUPD(uOut, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vOut, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)

	Label("first_loop_1_end")
	CMPQ(j, N)
	JL(LabelRef("first_loop_1_body"))

	XORQ(j, j)
	JMP(LabelRef("first_loop_2_end"))
	Label("first_loop_2_body")

	wR128, wI128 := XMM(), XMM()
	VMOVUPD(Mem{Base: twInv, Index: wIdx, Scale: 8}, wR128)
	VSHUFPD(Imm(0b11), wR128, wR128, wI128)
	VSHUFPD(Imm(0b00), wR128, wR128, wR128)
	ADDQ(Imm(2), wIdx)

	uR128, vR128 := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uR128)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16}, vR128)
	uI128, vI128 := XMM(), XMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uI128)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48}, vI128)

	InvButterflyAVX2XMM(uR128, uI128, vR128, vI128, wR128, wI128)

	VMOVUPD(uR128, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(vR128, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 16})
	VMOVUPD(uI128, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vI128, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 48})

	ADDQ(Imm(8), j)

	Label("first_loop_2_end")
	CMPQ(j, N)
	JL(LabelRef("first_loop_2_body"))

	t, m := GP64(), GP64()
	MOVQ(U64(8), t)
	MOVQ(N, m)
	SHRQ(Imm(4), m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop_body")

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("i_loop_end"))
	Label("i_loop_body")

	j1, j2 := GP64(), GP64()
	MOVQ(t, j1)
	IMULQ(i, j1)
	SHLQ(Imm(1), j1)
	MOVQ(j1, j2)
	ADDQ(t, j2)

	wR, wI := YMM(), YMM()
	VBROADCASTSD(Mem{Base: twInv, Index: wIdx, Scale: 8}, wR)
	VBROADCASTSD(Mem{Base: twInv, Index: wIdx, Scale: 8, Disp: 8}, wI)
	ADDQ(Imm(2), wIdx)

	j, jt := GP64(), GP64()
	MOVQ(j1, j)
	MOVQ(j2, jt)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop_body")

	uR, uI := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uR)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uI)
	vR, vI := YMM(), YMM()
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vR)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vI)

	InvButterflyAVX2(uR, uI, vR, vI, wR, wI)

	VMOVUPD(uR, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uI, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vR, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vI, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

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

	wR, wI = YMM(), YMM()
	VBROADCASTSD(Mem{Base: twInv, Index: wIdx, Scale: 8}, wR)
	VBROADCASTSD(Mem{Base: twInv, Index: wIdx, Scale: 8, Disp: 8}, wI)

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(1), M)

	XORQ(j, j)
	MOVQ(M, jt)
	JMP(LabelRef("last_loop_end"))
	Label("last_loop_body")

	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8}, uR)
	VMOVUPD(Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32}, uI)

	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8}, vR)
	VMOVUPD(Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32}, vI)

	InvButterflyAVX2(uR, uI, vR, vI, wR, wI)

	VMULPD(scale, uR, uR)
	VMULPD(scale, uI, uI)
	VMULPD(scale, vR, vR)
	VMULPD(scale, vI, vI)

	VMOVUPD(uR, Mem{Base: coeffs, Index: j, Scale: 8})
	VMOVUPD(uI, Mem{Base: coeffs, Index: j, Scale: 8, Disp: 32})
	VMOVUPD(vR, Mem{Base: coeffs, Index: jt, Scale: 8})
	VMOVUPD(vI, Mem{Base: coeffs, Index: jt, Scale: 8, Disp: 32})

	ADDQ(Imm(8), j)
	ADDQ(Imm(8), jt)

	Label("last_loop_end")
	CMPQ(j, M)
	JL(LabelRef("last_loop_body"))

	RET()
}

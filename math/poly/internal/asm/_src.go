//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func FFT() {
	TEXT("fftInPlaceAVX2", NOSPLIT, "func(coeffs, wNj []complex128)")

	coeffsPtr := Mem{Base: Load(Param("coeffs").Base(), GP64())}
	wNjPtr := Mem{Base: Load(Param("wNj").Base(), GP64())}

	N := Load(Param("coeffs").Len(), GP64())

	NHalf := GP64()
	MOVQ(N, NHalf)
	SHRQ(U8(1), NHalf)

	NN := GP64()
	MOVQ(N, NN)
	ADDQ(N, NN)

	Comment("t := N / 2")
	t := GP64()
	MOVQ(N, t)

	Comment("for m := 1; m < N/2; m <<= 1")
	m := GP64()
	MOVQ(U32(1), m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop")

	Comment("for i := 0; i < m; i++")
	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("i_loop_end"))
	Label("i_loop")

	Comment("Move wNj by one index")
	ADDQ(U8(16), wNjPtr.Base)

	Comment("Precompute wNj[m+i]")
	W := YMM()
	VBROADCASTF128(Mem{Base: wNjPtr.Base}, W)
	WSwap := YMM()
	VSHUFPD(U8(0b0101), W, W, WSwap)

	Comment("j1 := i * t << 1")
	j1 := GP64()
	MOVQ(i, j1)
	IMULQ(t, j1)
	SHLQ(U8(1), j1)

	Comment("j2 := j1 + t")
	j2 := GP64()
	MOVQ(j1, j2)
	ADDQ(t, j2)

	Comment("We increment j by 4 every iteration")
	Comment("for j := j1; j < j2; j++")
	j := GP64()
	MOVQ(j1, j)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop")

	Comment("U := coeffs[j]")
	U := YMM()
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: j, Scale: 8}, U)

	Comment("V := coeffs[j+t]")
	V := YMM()
	jt := GP64()
	MOVQ(j, jt)
	ADDQ(t, jt)
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: jt, Scale: 8}, V)

	Comment("V *= wNj[m+i]")
	VIm := YMM()
	VSHUFPD(U8(0b1111), V, V, VIm)
	VRe := YMM()
	VSHUFPD(U8(0b0000), V, V, VRe)
	VV := YMM()
	VMULPD(VIm, WSwap, VV)
	VFMADDSUB231PD(VRe, W, VV)

	Comment("coeffs[j] = U + V")
	X := YMM()
	VADDPD(U, VV, X)
	VMOVUPD(X, Mem{Base: coeffsPtr.Base, Index: j, Scale: 8})

	Comment("coeffs[j+t] = U - V")
	VSUBPD(VV, U, X)
	VMOVUPD(X, Mem{Base: coeffsPtr.Base, Index: jt, Scale: 8})

	Comment("j += 4")
	ADDQ(U8(4), j)

	Comment("j < j2")
	Label("j_loop_end")
	CMPQ(j, j2)
	JL(LabelRef("j_loop"))

	Comment("i++")
	INCQ(i)

	Comment("i < m")
	Label("i_loop_end")
	CMPQ(i, m)
	JL(LabelRef("i_loop"))

	Comment("t >>= 1")
	SHRQ(U8(1), t)

	Comment("m <<= 1")
	SHLQ(U8(1), m)

	Comment("m < N/2")
	Label("m_loop_end")
	CMPQ(m, NHalf)
	JL(LabelRef("m_loop"))

	Comment("Last Loop")

	Comment("for j := 0; j < N; j += 2")
	XORQ(j, j)
	JMP(LabelRef("last_loop_end"))
	Label("last_loop")

	Comment("Move wNj by one index")
	ADDQ(U8(16), wNjPtr.Base)

	Comment("Precompute wNj[m+i]")
	W128 := XMM()
	VMOVUPD(Mem{Base: wNjPtr.Base}, W128)
	WSwap128 := XMM()
	VSHUFPD(U8(0b01), W128, W128, WSwap128)

	Comment("U := coeffs[j]")
	U128 := XMM()
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: j, Scale: 8}, U128)

	Comment("V := coeffs[j+1]")
	V128 := XMM()
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: j, Scale: 8, Disp: 16}, V128)

	Comment("V *= wNj[m+i]")
	VIm128 := XMM()
	VSHUFPD(U8(0b11), V128, V128, VIm128)
	VRe128 := XMM()
	VSHUFPD(U8(0b00), V128, V128, VRe128)
	VV128 := XMM()
	VMULPD(VIm128, WSwap128, VV128)
	VFMADDSUB231PD(VRe128, W128, VV128)

	Comment("coeffs[j] = U + V")
	X128 := XMM()
	VADDPD(U128, VV128, X128)
	VMOVUPD(X128, Mem{Base: coeffsPtr.Base, Index: j, Scale: 8})

	Comment("coeffs[j+1] = U - V")
	VSUBPD(VV128, U128, X128)
	VMOVUPD(X128, Mem{Base: coeffsPtr.Base, Index: j, Scale: 8, Disp: 16})

	Comment("j += 2")
	ADDQ(U8(4), j)

	Comment("j < N")
	Label("last_loop_end")
	CMPQ(j, NN)
	JL(LabelRef("last_loop"))

	RET()
}

func InvFFT() {
	TEXT("invFFTInPlaceAVX2", NOSPLIT, "func(coeffs, wNjInv []complex128)")

	coeffsPtr := Mem{Base: Load(Param("coeffs").Base(), GP64())}
	wNjInvPtr := Mem{Base: Load(Param("wNjInv").Base(), GP64())}

	N := Load(Param("coeffs").Len(), GP64())

	NN := GP64()
	MOVQ(N, NN)
	ADDQ(N, NN)

	N2 := GP64()
	MOVQ(N, N2)
	SHRQ(U8(1), N2)

	Comment("First Loop")

	Comment("hi := N / 2")
	hi := GP64()
	MOVQ(N, hi)

	Comment("for j := 0; j < N; j += 2")
	j := GP64()
	XORQ(j, j)
	JMP(LabelRef("first_loop_end"))
	Label("first_loop")

	Comment("Index wNjInv")
	W128 := XMM()
	VMOVUPD(Mem{Base: wNjInvPtr.Base, Index: hi, Scale: 8}, W128)

	Comment("Precompute wNjInv[hi]")
	WSwap128 := XMM()
	VSHUFPD(U8(0b01), W128, W128, WSwap128)

	Comment("U := coeffs[j]")
	U128 := XMM()
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: j, Scale: 8}, U128)

	Comment("V := coeffs[j+1]")
	V128 := XMM()
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: j, Scale: 8, Disp: 16}, V128)

	Comment("coeffs[j] = U + V")
	X128 := XMM()
	VADDPD(U128, V128, X128)
	VMOVUPD(X128, Mem{Base: coeffsPtr.Base, Index: j, Scale: 8})

	Comment("coeffs[j+1] = (U - V) * wNjInv[hi]")
	VSUBPD(V128, U128, X128)
	XIm128 := XMM()
	VSHUFPD(U8(0b11), X128, X128, XIm128)
	XRe128 := XMM()
	VSHUFPD(U8(0b00), X128, X128, XRe128)
	XX128 := XMM()
	VMULPD(XIm128, WSwap128, XX128)
	VFMADDSUB231PD(XRe128, W128, XX128)
	VMOVUPD(XX128, Mem{Base: coeffsPtr.Base, Index: j, Scale: 8, Disp: 16})

	Comment("hi++")
	ADDQ(U8(2), hi)

	Comment("j += 2")
	ADDQ(U8(4), j)

	Comment("j < N")
	Label("first_loop_end")
	CMPQ(j, NN)
	JL(LabelRef("first_loop"))

	Comment("t := 2")
	t := GP64()
	MOVQ(U32(4), t)

	Comment("for m := N / 2; m > 1; m >>= 1")
	m := GP64()
	MOVQ(N2, m)
	JMP(LabelRef("m_loop_end"))
	Label("m_loop")

	Comment("j1 := 0")
	j1 := GP64()
	XORQ(j1, j1)

	Comment("h := m >> 1")
	h := GP64()
	MOVQ(m, h)

	Comment("for i := 0; i < h; i++")
	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("i_loop_end"))
	Label("i_loop")

	Comment("Index wNjInv")
	MOVQ(h, hi)
	ADDQ(i, hi)
	W := YMM()
	VBROADCASTF128(Mem{Base: wNjInvPtr.Base, Index: hi, Scale: 8}, W)

	Comment("Precompute wNjInv[h+i]")
	WSwap := YMM()
	VSHUFPD(U8(0b0101), W, W, WSwap)

	Comment("j2 := j1 + t")
	j2 := GP64()
	MOVQ(j1, j2)
	ADDQ(t, j2)

	Comment("We increment j by 4 every iteration")
	Comment("for j := j1; j < j2; j++")
	MOVQ(j1, j)
	JMP(LabelRef("j_loop_end"))
	Label("j_loop")

	Comment("U := coeffs[j]")
	U := YMM()
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: j, Scale: 8}, U)

	Comment("V := coeffs[j+t]")
	V := YMM()
	jt := GP64()
	MOVQ(j, jt)
	ADDQ(t, jt)
	VMOVUPD(Mem{Base: coeffsPtr.Base, Index: jt, Scale: 8}, V)

	Comment("coeffs[j] = U + V")
	X := YMM()
	VADDPD(U, V, X)
	VMOVUPD(X, Mem{Base: coeffsPtr.Base, Index: j, Scale: 8})

	Comment("coeffs[j+t] = (U - V) * wNjInv[h+i]")
	VSUBPD(V, U, X)
	XIm := YMM()
	VSHUFPD(U8(0b1111), X, X, XIm)
	XRe := YMM()
	VSHUFPD(U8(0b0000), X, X, XRe)
	XX := YMM()
	VMULPD(XIm, WSwap, XX)
	VFMADDSUB231PD(XRe, W, XX)
	VMOVUPD(XX, Mem{Base: coeffsPtr.Base, Index: jt, Scale: 8})

	Comment("j += 4")
	ADDQ(U8(4), j)

	Comment("j < j2")
	Label("j_loop_end")
	CMPQ(j, j2)
	JL(LabelRef("j_loop"))

	Comment("j1 += t << 1")
	tt := GP64()
	MOVQ(t, tt)
	SHLQ(U8(1), tt)
	ADDQ(tt, j1)

	Comment("i++")
	ADDQ(U8(2), i)

	Comment("i < h")
	Label("i_loop_end")
	CMPQ(i, h)
	JL(LabelRef("i_loop"))

	Comment("t <<= 1")
	SHLQ(U8(1), t)

	Comment("m >>= 1")
	SHRQ(U8(1), m)

	Comment("m > 1")
	Label("m_loop_end")
	CMPQ(m, U32(1))
	JG(LabelRef("m_loop"))

	RET()
}

func main() {
	FFT()
	InvFFT()

	Generate()
}

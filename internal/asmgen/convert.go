package main

import (
	"math"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

func convertConstants() {
	ConstData("EXP2_52", F64(math.Exp2(52)))
	ConstData("EXP2_84_63", F64(math.Exp2(84)+math.Exp2(63)))
	ConstData("EXP2_84_63_52", F64(math.Exp2(84)+math.Exp2(63)+math.Exp2(52)))

	ConstData("MANT_MASK", U64((1<<52)-1))
	ConstData("BIT_MANT_MASK", U64(1<<52))
	ConstData("EXP_MASK", U64((1<<11)-1))
	ConstData("EXP_SHIFT", U64(1023+52+11))
}

func convertPolyToFourierPolyAssignUint32AVX2() {
	TEXT("convertPolyToFourierPolyAssignUint32AVX2", NOSPLIT, "func(p []uint32, fpOut []float64)")
	Pragma("noescape")

	p := Load(Param("p").Base(), GP64())
	fpOut := Load(Param("fpOut").Base(), GP64())
	N := Load(Param("fpOut").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := XMM(), XMM()
	VMOVDQU(Mem{Base: p, Index: ii0, Scale: 4}, c0)
	VMOVDQU(Mem{Base: p, Index: ii1, Scale: 4}, c1)

	cOut0, cOut1 := YMM(), YMM()
	VCVTDQ2PD(c0, cOut0)
	VCVTDQ2PD(c1, cOut1)

	VMOVUPD(cOut0, Mem{Base: fpOut, Index: i, Scale: 8})
	VMOVUPD(cOut1, Mem{Base: fpOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertInt64ToFloat64(cvtConst [3]reg.VecVirtual, c, cOut reg.VecVirtual) {
	exp2_52, exp2_84_63, exp2_84_63_52 := cvtConst[0], cvtConst[1], cvtConst[2]

	cLo := YMM()
	VPBLENDD(Imm(0b01010101), c, exp2_52, cLo)

	cHi := YMM()
	VPSRLQ(Imm(32), c, cHi)
	VPXOR(exp2_84_63, cHi, cHi)

	VSUBPD(exp2_84_63_52, cHi, cOut)
	VADDPD(cOut, cLo, cOut)
}

func convertPolyToFourierPolyAssignUint64AVX2() {
	TEXT("convertPolyToFourierPolyAssignUint64AVX2", NOSPLIT, "func(p []uint64, fpOut []float64)")
	Pragma("noescape")

	p := Load(Param("p").Base(), GP64())
	fpOut := Load(Param("fpOut").Base(), GP64())
	N := Load(Param("fpOut").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	exp2_52, exp2_84_63, exp2_84_63_52 := YMM(), YMM(), YMM()
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP2_52"), 0), exp2_52)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP2_84_63"), 0), exp2_84_63)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP2_84_63_52"), 0), exp2_84_63_52)
	cvtConst := [3]reg.VecVirtual{exp2_52, exp2_84_63, exp2_84_63_52}

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVDQU(Mem{Base: p, Index: ii0, Scale: 8}, c0)
	VMOVDQU(Mem{Base: p, Index: ii1, Scale: 8}, c1)

	cOut0, cOut1 := YMM(), YMM()
	convertInt64ToFloat64(cvtConst, c0, cOut0)
	convertInt64ToFloat64(cvtConst, c1, cOut1)

	VMOVUPD(cOut0, Mem{Base: fpOut, Index: i, Scale: 8})
	VMOVUPD(cOut1, Mem{Base: fpOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func floatModQInPlaceAVX2() {
	TEXT("floatModQInPlaceAVX2", NOSPLIT, "func(coeffs []float64, Q, QInv float64)")
	Pragma("noescape")

	coeffs := Load(Param("coeffs").Base(), GP64())
	N := Load(Param("coeffs").Len(), GP64())

	Q, QInv := YMM(), YMM()
	VBROADCASTSD(NewParamAddr("Q", 24), Q)
	VBROADCASTSD(NewParamAddr("QInv", 32), QInv)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c := YMM()
	VMOVUPD(Mem{Base: coeffs, Index: i, Scale: 8}, c)

	cQuo, cQuoRound := YMM(), YMM()
	VMULPD(QInv, c, cQuo)
	VROUNDPD(Imm(0), cQuo, cQuoRound)

	cRem, cOut := YMM(), YMM()
	VSUBPD(cQuoRound, cQuo, cRem)
	VMULPD(Q, cRem, cOut)
	VROUNDPD(Imm(0), cOut, cOut)

	VMOVUPD(cOut, Mem{Base: coeffs, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertFourierPolyToPolyAssignUint32AVX2() {
	TEXT("convertFourierPolyToPolyAssignUint32AVX2", NOSPLIT, "func(fp []float64, pOut []uint32)")
	Pragma("noescape")

	fp := Load(Param("fp").Base(), GP64())
	pOut := Load(Param("pOut").Base(), GP64())
	N := Load(Param("fp").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8}, c0)
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8, Disp: 32}, c1)

	c0Out, c1Out := XMM(), XMM()
	VCVTPD2DQY(c0, c0Out)
	VCVTPD2DQY(c1, c1Out)

	VMOVDQU(c0Out, Mem{Base: pOut, Index: ii0, Scale: 4})
	VMOVDQU(c1Out, Mem{Base: pOut, Index: ii1, Scale: 4})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertFourierPolyToPolyAddAssignUint32AVX2() {
	TEXT("convertFourierPolyToPolyAddAssignUint32AVX2", NOSPLIT, "func(fp []float64, pOut []uint32)")
	Pragma("noescape")

	fp := Load(Param("fp").Base(), GP64())
	pOut := Load(Param("pOut").Base(), GP64())
	N := Load(Param("fp").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8}, c0)
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8, Disp: 32}, c1)

	c0Out, c1Out := XMM(), XMM()
	VMOVUPD(Mem{Base: pOut, Index: ii0, Scale: 4}, c0Out)
	VMOVUPD(Mem{Base: pOut, Index: ii1, Scale: 4}, c1Out)

	c0Cvt, c1Cvt := XMM(), XMM()
	VCVTPD2DQY(c0, c0Cvt)
	VCVTPD2DQY(c1, c1Cvt)

	VPADDD(c0Cvt, c0Out, c0Out)
	VPADDD(c1Cvt, c1Out, c1Out)

	VMOVDQU(c0Out, Mem{Base: pOut, Index: ii0, Scale: 4})
	VMOVDQU(c1Out, Mem{Base: pOut, Index: ii1, Scale: 4})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertFourierPolyToPolySubAssignUint32AVX2() {
	TEXT("convertFourierPolyToPolySubAssignUint32AVX2", NOSPLIT, "func(fp []float64, pOut []uint32)")
	Pragma("noescape")

	fp := Load(Param("fp").Base(), GP64())
	pOut := Load(Param("pOut").Base(), GP64())
	N := Load(Param("fp").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8}, c0)
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8, Disp: 32}, c1)

	c0Out, c1Out := XMM(), XMM()
	VMOVUPD(Mem{Base: pOut, Index: ii0, Scale: 4}, c0Out)
	VMOVUPD(Mem{Base: pOut, Index: ii1, Scale: 4}, c1Out)

	c0Cvt, c1Cvt := XMM(), XMM()
	VCVTPD2DQY(c0, c0Cvt)
	VCVTPD2DQY(c1, c1Cvt)

	VPSUBD(c0Cvt, c0Out, c0Out)
	VPSUBD(c1Cvt, c1Out, c1Out)

	VMOVDQU(c0Out, Mem{Base: pOut, Index: ii0, Scale: 4})
	VMOVDQU(c1Out, Mem{Base: pOut, Index: ii1, Scale: 4})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertFloat64ToInt64(cvtConst [5]reg.VecVirtual, c, cOut reg.VecVirtual) {
	mantMask, bitMantMask, expMask, expShift, zero := cvtConst[0], cvtConst[1], cvtConst[2], cvtConst[3], cvtConst[4]

	cMant := YMM()
	VANDPD(mantMask, c, cMant)
	VORPD(bitMantMask, cMant, cMant)

	cExp := YMM()
	VPSRLQ(Imm(52), c, cExp)
	VANDPD(expMask, cExp, cExp)

	cSign := YMM()
	VPSRLQ(Imm(63), c, cSign)
	VPSUBQ(cSign, zero, cSign)

	cMantPos := YMM()
	VPSLLQ(Imm(11), cMant, cMantPos)
	VPSUBQ(cExp, expShift, cExp)
	VPSRLVQ(cExp, cMantPos, cMantPos)

	cMantNeg := YMM()
	VPSUBQ(cMantPos, zero, cMantNeg)

	VPBLENDVB(cSign, cMantNeg, cMantPos, cOut)
}

func convertFourierPolyToPolyAssignUint64AVX2() {
	TEXT("convertFourierPolyToPolyAssignUint64AVX2", NOSPLIT, "func(fp []float64, pOut []uint64)")
	Pragma("noescape")

	fp := Load(Param("fp").Base(), GP64())
	pOut := Load(Param("pOut").Base(), GP64())
	N := Load(Param("fp").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	mantMask, bitMantMask, expMask, expShift := YMM(), YMM(), YMM(), YMM()
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("MANT_MASK"), 0), mantMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("BIT_MANT_MASK"), 0), bitMantMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP_MASK"), 0), expMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP_SHIFT"), 0), expShift)

	zero := YMM()
	VPXOR(zero, zero, zero)

	cvtConst := [5]reg.VecVirtual{mantMask, bitMantMask, expMask, expShift, zero}

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8}, c0)
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8, Disp: 32}, c1)

	c0Out, c1Out := YMM(), YMM()
	convertFloat64ToInt64(cvtConst, c0, c0Out)
	convertFloat64ToInt64(cvtConst, c1, c1Out)

	VMOVDQU(c0Out, Mem{Base: pOut, Index: ii0, Scale: 8})
	VMOVDQU(c1Out, Mem{Base: pOut, Index: ii1, Scale: 8})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertFourierPolyToPolyAddAssignUint64AVX2() {
	TEXT("convertFourierPolyToPolyAddAssignUint64AVX2", NOSPLIT, "func(fp []float64, pOut []uint64)")
	Pragma("noescape")

	fp := Load(Param("fp").Base(), GP64())
	pOut := Load(Param("pOut").Base(), GP64())
	N := Load(Param("fp").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	mantMask, bitMantMask, expMask, expShift := YMM(), YMM(), YMM(), YMM()
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("MANT_MASK"), 0), mantMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("BIT_MANT_MASK"), 0), bitMantMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP_MASK"), 0), expMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP_SHIFT"), 0), expShift)

	zero := YMM()
	VPXOR(zero, zero, zero)

	cvtConst := [5]reg.VecVirtual{mantMask, bitMantMask, expMask, expShift, zero}

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8}, c0)
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8, Disp: 32}, c1)
	c0Out, c1Out := YMM(), YMM()
	VMOVDQU(Mem{Base: pOut, Index: ii0, Scale: 8}, c0Out)
	VMOVDQU(Mem{Base: pOut, Index: ii1, Scale: 8}, c1Out)

	c0Cvt, c1Cvt := YMM(), YMM()
	convertFloat64ToInt64(cvtConst, c0, c0Cvt)
	convertFloat64ToInt64(cvtConst, c1, c1Cvt)

	VPADDQ(c0Cvt, c0Out, c0Out)
	VPADDQ(c1Cvt, c1Out, c1Out)

	VMOVDQU(c0Out, Mem{Base: pOut, Index: ii0, Scale: 8})
	VMOVDQU(c1Out, Mem{Base: pOut, Index: ii1, Scale: 8})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func convertFourierPolyToPolySubAssignUint64AVX2() {
	TEXT("convertFourierPolyToPolySubAssignUint64AVX2", NOSPLIT, "func(fp []float64, pOut []uint64)")
	Pragma("noescape")

	fp := Load(Param("fp").Base(), GP64())
	pOut := Load(Param("pOut").Base(), GP64())
	N := Load(Param("fp").Len(), GP64())

	NMul2 := GP64()
	MOVQ(N, NMul2)
	SHRQ(U8(1), NMul2)

	mantMask, bitMantMask, expMask, expShift := YMM(), YMM(), YMM(), YMM()
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("MANT_MASK"), 0), mantMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("BIT_MANT_MASK"), 0), bitMantMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP_MASK"), 0), expMask)
	VBROADCASTSD(NewDataAddr(NewStaticSymbol("EXP_SHIFT"), 0), expShift)

	zero := YMM()
	VPXOR(zero, zero, zero)

	cvtConst := [5]reg.VecVirtual{mantMask, bitMantMask, expMask, expShift, zero}

	i, ii0, ii1 := GP64(), GP64(), GP64()
	XORQ(i, i)
	XORQ(ii0, ii0)
	MOVQ(NMul2, ii1)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	c0, c1 := YMM(), YMM()
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8}, c0)
	VMOVUPD(Mem{Base: fp, Index: i, Scale: 8, Disp: 32}, c1)
	c0Out, c1Out := YMM(), YMM()
	VMOVDQU(Mem{Base: pOut, Index: ii0, Scale: 8}, c0Out)
	VMOVDQU(Mem{Base: pOut, Index: ii1, Scale: 8}, c1Out)

	c0Cvt, c1Cvt := YMM(), YMM()
	convertFloat64ToInt64(cvtConst, c0, c0Cvt)
	convertFloat64ToInt64(cvtConst, c1, c1Cvt)

	VPSUBQ(c0Cvt, c0Out, c0Out)
	VPSUBQ(c1Cvt, c1Out, c1Out)

	VMOVDQU(c0Out, Mem{Base: pOut, Index: ii0, Scale: 8})
	VMOVDQU(c1Out, Mem{Base: pOut, Index: ii1, Scale: 8})

	ADDQ(Imm(8), i)
	ADDQ(Imm(4), ii0)
	ADDQ(Imm(4), ii1)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func AddSubCmplxToAVX2(opType OpType) {
	switch opType {
	case OpAdd:
		TEXT("addCmplxToAVX2", NOSPLIT, "func(vOut, v0, v1 []float64)")
	case OpSub:
		TEXT("subCmplxToAVX2", NOSPLIT, "func(vOut, v0, v1 []float64)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0, x1 := YMM(), YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)
	VMOVUPD(Mem{Base: v1, Index: i, Scale: 8}, x1)

	xOut := YMM()
	switch opType {
	case OpAdd:
		VADDPD(x1, x0, xOut)
	case OpSub:
		VSUBPD(x1, x0, xOut)
	}

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func NegCmplxToAVX2() {
	TEXT("negCmplxToAVX2", NOSPLIT, "func(vOut, v []float64)")
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v := Load(Param("v").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	zero := YMM()
	VXORPD(zero, zero, zero)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x := YMM()
	VMOVUPD(Mem{Base: v, Index: i, Scale: 8}, x)

	xOut := YMM()
	VSUBPD(x, zero, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func FloatMulCmplxToAVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("floatMulCmplxToAVX2", NOSPLIT, "func(vOut, v []float64, c float64)")
	case OpAdd:
		TEXT("floatMulAddCmplxToAVX2", NOSPLIT, "func(vOut, v []float64, c float64)")
	case OpSub:
		TEXT("floatMulSubCmplxToAVX2", NOSPLIT, "func(vOut, v []float64, c float64)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v := Load(Param("v").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	c := YMM()
	VBROADCASTSD(NewParamAddr("c", 48), c)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x := YMM()
	VMOVUPD(Mem{Base: v, Index: i, Scale: 8}, x)

	xOut := YMM()
	switch opType {
	case OpPure:
		VMULPD(c, x, xOut)
	case OpAdd:
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOut)
		VFMADD231PD(c, x, xOut)
	case OpSub:
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOut)
		VFNMADD231PD(c, x, xOut)
	}

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func CmplxMulCmplxToAVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("cmplxMulCmplxToAVX2", NOSPLIT, "func(vOut, v []float64, c complex128)")
	case OpAdd:
		TEXT("cmplxMulAddCmplxToAVX2", NOSPLIT, "func(vOut, v []float64, c complex128)")
	case OpSub:
		TEXT("cmplxMulSubCmplxToAVX2", NOSPLIT, "func(vOut, v []float64, c complex128)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v := Load(Param("v").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	cReal, cImag := YMM(), YMM()
	VBROADCASTSD(NewParamAddr("c_real", 48), cReal)
	VBROADCASTSD(NewParamAddr("c_imag", 56), cImag)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	xReal, xImag := YMM(), YMM()
	VMOVUPD(Mem{Base: v, Index: i, Scale: 8}, xReal)
	VMOVUPD(Mem{Base: v, Index: i, Scale: 8, Disp: 32}, xImag)

	xOutReal, xOutImag := YMM(), YMM()
	switch opType {
	case OpPure:
		VMULPD(cReal, xReal, xOutReal)
		VFNMADD231PD(cImag, xImag, xOutReal)

		VMULPD(cReal, xImag, xOutImag)
		VFMADD231PD(cImag, xReal, xOutImag)
	case OpAdd:
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

		VFMADD231PD(cReal, xReal, xOutReal)
		VFNMADD231PD(cImag, xImag, xOutReal)

		VFMADD231PD(cReal, xImag, xOutImag)
		VFMADD231PD(cImag, xReal, xOutImag)
	case OpSub:
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

		VFNMADD231PD(cReal, xReal, xOutReal)
		VFMADD231PD(cImag, xImag, xOutReal)

		VFNMADD231PD(cReal, xImag, xOutImag)
		VFNMADD231PD(cImag, xReal, xOutImag)
	}

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func MulCmplxToAVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("mulCmplxToAVX2", NOSPLIT, "func(vOut, v0, v1 []float64)")
	case OpAdd:
		TEXT("mulAddCmplxToAVX2", NOSPLIT, "func(vOut, v0, v1 []float64)")
	case OpSub:
		TEXT("mulSubCmplxToAVX2", NOSPLIT, "func(vOut, v0, v1 []float64)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0Real, x0Imag := YMM(), YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0Real)
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8, Disp: 32}, x0Imag)
	x1Real, x1Imag := YMM(), YMM()
	VMOVUPD(Mem{Base: v1, Index: i, Scale: 8}, x1Real)
	VMOVUPD(Mem{Base: v1, Index: i, Scale: 8, Disp: 32}, x1Imag)

	xOutReal, xOutImag := YMM(), YMM()
	switch opType {
	case OpPure:
		VMULPD(x0Real, x1Real, xOutReal)
		VFNMADD231PD(x0Imag, x1Imag, xOutReal)

		VMULPD(x0Real, x1Imag, xOutImag)
		VFMADD231PD(x0Imag, x1Real, xOutImag)
	case OpAdd:
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

		VFMADD231PD(x0Real, x1Real, xOutReal)
		VFNMADD231PD(x0Imag, x1Imag, xOutReal)

		VFMADD231PD(x0Real, x1Imag, xOutImag)
		VFMADD231PD(x0Imag, x1Real, xOutImag)
	case OpSub:
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
		VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

		VFNMADD231PD(x0Real, x1Real, xOutReal)
		VFMADD231PD(x0Imag, x1Imag, xOutReal)

		VFNMADD231PD(x0Real, x1Imag, xOutImag)
		VFNMADD231PD(x0Imag, x1Real, xOutImag)
	}

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

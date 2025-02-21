package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func addCmplxAssignAVX2() {
	TEXT("addCmplxAssignAVX2", NOSPLIT, "func(v0, v1, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)
	x1 := YMM()
	VMOVUPD(Mem{Base: v1, Index: i, Scale: 8}, x1)

	xOut := YMM()
	VADDPD(x1, x0, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func subCmplxAssignAVX2() {
	TEXT("subCmplxAssignAVX2", NOSPLIT, "func(v0, v1, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)
	x1 := YMM()
	VMOVUPD(Mem{Base: v1, Index: i, Scale: 8}, x1)

	xOut := YMM()
	VSUBPD(x1, x0, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func negCmplxAssignAVX2() {
	TEXT("negCmplxAssignAVX2", NOSPLIT, "func(v0, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	zero := YMM()
	VXORPD(zero, zero, zero)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)

	xOut := YMM()
	VSUBPD(x0, zero, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func floatMulCmplxAssignAVX2() {
	TEXT("floatMulCmplxAssignAVX2", NOSPLIT, "func(v0 []float64, c float64, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	c := YMM()
	VBROADCASTSD(NewParamAddr("c", 24), c)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)

	xOut := YMM()
	VMULPD(c, x0, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func floatMulAddCmplxAssignAVX2() {
	TEXT("floatMulAddCmplxAssignAVX2", NOSPLIT, "func(v0 []float64, c float64, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	c := YMM()
	VBROADCASTSD(NewParamAddr("c", 24), c)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)
	xOut := YMM()
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOut)

	VFMADD231PD(c, x0, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func floatMulSubCmplxAssignAVX2() {
	TEXT("floatMulSubCmplxAssignAVX2", NOSPLIT, "func(v0 []float64, c float64, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	c := YMM()
	VBROADCASTSD(NewParamAddr("c", 24), c)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0)
	xOut := YMM()
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOut)

	VFNMADD231PD(c, x0, xOut)

	VMOVUPD(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func cmplxMulCmplxAssignAVX2() {
	TEXT("cmplxMulCmplxAssignAVX2", NOSPLIT, "func(v0 []float64, c complex128, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	cReal, cImag := YMM(), YMM()
	VBROADCASTSD(NewParamAddr("c_real", 24), cReal)
	VBROADCASTSD(NewParamAddr("c_imag", 32), cImag)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0Real, x0Imag := YMM(), YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0Real)
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8, Disp: 32}, x0Imag)

	xOutReal := YMM()
	VMULPD(cReal, x0Real, xOutReal)
	VFNMADD231PD(cImag, x0Imag, xOutReal)

	xOutImag := YMM()
	VMULPD(cReal, x0Imag, xOutImag)
	VFMADD231PD(cImag, x0Real, xOutImag)

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func cmplxMulAddCmplxAssignAVX2() {
	TEXT("cmplxMulAddCmplxAssignAVX2", NOSPLIT, "func(v0 []float64, c complex128, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	cReal, cImag := YMM(), YMM()
	VBROADCASTSD(NewParamAddr("c_real", 24), cReal)
	VBROADCASTSD(NewParamAddr("c_imag", 32), cImag)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0Real, x0Imag := YMM(), YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0Real)
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8, Disp: 32}, x0Imag)
	xOutReal, xOutImag := YMM(), YMM()
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

	VFMADD231PD(cReal, x0Real, xOutReal)
	VFNMADD231PD(cImag, x0Imag, xOutReal)

	VFMADD231PD(cReal, x0Imag, xOutImag)
	VFMADD231PD(cImag, x0Real, xOutImag)

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func cmplxMulSubCmplxAssignAVX2() {
	TEXT("cmplxMulSubCmplxAssignAVX2", NOSPLIT, "func(v0 []float64, c complex128, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	cReal, cImag := YMM(), YMM()
	VBROADCASTSD(NewParamAddr("c_real", 24), cReal)
	VBROADCASTSD(NewParamAddr("c_imag", 32), cImag)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0Real, x0Imag := YMM(), YMM()
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8}, x0Real)
	VMOVUPD(Mem{Base: v0, Index: i, Scale: 8, Disp: 32}, x0Imag)
	xOutReal, xOutImag := YMM(), YMM()
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

	VFNMADD231PD(cReal, x0Real, xOutReal)
	VFMADD231PD(cImag, x0Imag, xOutReal)

	VFNMADD231PD(cReal, x0Imag, xOutImag)
	VFNMADD231PD(cImag, x0Real, xOutImag)

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func elementWiseMulCmplxAssignAVX2() {
	TEXT("elementWiseMulCmplxAssignAVX2", NOSPLIT, "func(v0, v1, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
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

	xOutReal := YMM()
	VMULPD(x0Real, x1Real, xOutReal)
	VFNMADD231PD(x0Imag, x1Imag, xOutReal)

	xOutImag := YMM()
	VMULPD(x0Real, x1Imag, xOutImag)
	VFMADD231PD(x0Imag, x1Real, xOutImag)

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func elementWiseMulAddCmplxAssignAVX2() {
	TEXT("elementWiseMulAddCmplxAssignAVX2", NOSPLIT, "func(v0, v1, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
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
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

	VFMADD231PD(x0Real, x1Real, xOutReal)
	VFNMADD231PD(x0Imag, x1Imag, xOutReal)

	VFMADD231PD(x0Real, x1Imag, xOutImag)
	VFMADD231PD(x0Imag, x1Real, xOutImag)

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

func elementWiseMulSubCmplxAssignAVX2() {
	TEXT("elementWiseMulSubCmplxAssignAVX2", NOSPLIT, "func(v0, v1, vOut []float64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
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
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8}, xOutReal)
	VMOVUPD(Mem{Base: vOut, Index: i, Scale: 8, Disp: 32}, xOutImag)

	VFNMADD231PD(x0Real, x1Real, xOutReal)
	VFMADD231PD(x0Imag, x1Imag, xOutReal)

	VFNMADD231PD(x0Real, x1Imag, xOutImag)
	VFNMADD231PD(x0Imag, x1Real, xOutImag)

	VMOVUPD(xOutReal, Mem{Base: vOut, Index: i, Scale: 8})
	VMOVUPD(xOutImag, Mem{Base: vOut, Index: i, Scale: 8, Disp: 32})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, N)
	JL(LabelRef("loop_body"))

	RET()
}

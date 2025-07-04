package main

import (
	"math"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

func vecConstants() {
	ConstData("MASK_HI", U64(math.MaxUint32<<32))
}

func addAssignUint32AVX2() {
	TEXT("addAssignUint32AVX2", NOSPLIT, "func(v0, v1, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0, x1 := YMM(), YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 4}, x1)

	xOut := YMM()
	VPADDD(x1, x0, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0, y1 := GP32(), GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	MOVL(Mem{Base: v1, Index: i, Scale: 4}, y1)

	ADDL(y1, y0)

	MOVL(y0, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func subAssignUint32AVX2() {
	TEXT("subAssignUint32AVX2", NOSPLIT, "func(v0, v1, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0, x1 := YMM(), YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 4}, x1)

	xOut := YMM()
	VPSUBD(x1, x0, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0, y1 := GP32(), GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	MOVL(Mem{Base: v1, Index: i, Scale: 4}, y1)

	SUBL(y1, y0)

	MOVL(y0, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func addAssignUint64AVX2() {
	TEXT("addAssignUint64AVX2", NOSPLIT, "func(v0, v1, vOut []uint64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0, x1 := YMM(), YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 8}, x1)

	xOut := YMM()
	VPADDQ(x1, x0, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0, y1 := GP64(), GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	MOVQ(Mem{Base: v1, Index: i, Scale: 8}, y1)

	ADDQ(y1, y0)

	MOVQ(y0, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func subAssignUint64AVX2() {
	TEXT("subAssignUint64AVX2", NOSPLIT, "func(v0, v1, vOut []uint64)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0, x1 := YMM(), YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 8}, x1)

	xOut := YMM()
	VPSUBQ(x1, x0, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0, y1 := GP64(), GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	MOVQ(Mem{Base: v1, Index: i, Scale: 8}, y1)

	SUBQ(y1, y0)

	MOVQ(y0, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func scalarMulAssignUint32AVX2() {
	TEXT("scalarMulAssignUint32AVX2", NOSPLIT, "func(v0 []uint32, c uint32, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	cv := YMM()
	VPBROADCASTD(NewParamAddr("c", 24), cv)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)

	xOut := YMM()
	VPMULLD(cv, x0, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	c := GP32()
	Load(Param("c"), c)

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")
	y0 := GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)

	IMULL(c, y0)

	MOVL(y0, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func scalarMulAddAssignUint32AVX2() {
	TEXT("scalarMulAddAssignUint32AVX2", NOSPLIT, "func(v0 []uint32, c uint32, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	cv := YMM()
	VPBROADCASTD(NewParamAddr("c", 24), cv)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)

	VPMULLD(cv, x0, x0)
	VPADDD(x0, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	c := GP32()
	Load(Param("c"), c)

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")
	y0 := GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	yOut := GP32()
	MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)

	IMULL(c, y0)
	ADDL(y0, yOut)

	MOVL(yOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func scalarMulSubAssignUint32AVX2() {
	TEXT("scalarMulSubAssignUint32AVX2", NOSPLIT, "func(v0 []uint32, c uint32, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	cv := YMM()
	VPBROADCASTD(NewParamAddr("c", 24), cv)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)

	VPMULLD(cv, x0, x0)
	VPSUBD(x0, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	c := GP32()
	Load(Param("c"), c)

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")
	y0 := GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	yOut := GP32()
	MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)

	IMULL(c, y0)
	SUBL(y0, yOut)

	MOVL(yOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func elementWiseMulAssignUint32AVX2() {
	TEXT("elementWiseMulAssignUint32AVX2", NOSPLIT, "func(v0, v1, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	x1 := YMM()
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 4}, x1)

	xOut := YMM()
	VPMULLD(x1, x0, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	y1 := GP32()
	MOVL(Mem{Base: v1, Index: i, Scale: 4}, y1)

	IMULL(y1, y0)

	MOVL(y0, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func elementWiseMulAddAssignUint32AVX2() {
	TEXT("elementWiseMulAddAssignUint32AVX2", NOSPLIT, "func(v0, v1, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	x1 := YMM()
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 4}, x1)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)

	VPMULLD(x1, x0, x0)
	VPADDD(x0, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	y1 := GP32()
	MOVL(Mem{Base: v1, Index: i, Scale: 4}, y1)
	yOut := GP32()
	MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)

	IMULL(y1, y0)
	ADDL(y0, yOut)

	MOVL(yOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func elementWiseMulSubAssignUint32AVX2() {
	TEXT("elementWiseMulSubAssignUint32AVX2", NOSPLIT, "func(v0, v1, vOut []uint32)")
	Pragma("noescape")

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 4}, x0)
	x1 := YMM()
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 4}, x1)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)

	VPMULLD(x1, x0, x0)
	VPSUBD(x0, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP32()
	MOVL(Mem{Base: v0, Index: i, Scale: 4}, y0)
	y1 := GP32()
	MOVL(Mem{Base: v1, Index: i, Scale: 4}, y1)
	yOut := GP32()
	MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)

	IMULL(y1, y0)
	SUBL(y0, yOut)

	MOVL(yOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func shuffleForLoAVX2(x, xSwap reg.VecVirtual) {
	VPSHUFD(Imm(0b10_11_00_01), x, xSwap)
}

func mul64LoAVX2(x0, x1, x1Swap, maskHi, xOut reg.VecVirtual) {
	xLoLo := YMM()
	VPMULUDQ(x1, x0, xLoLo)

	xMid0, xMid1 := YMM(), YMM()
	VPMULLD(x1Swap, x0, xMid0)
	VPSLLQ(Imm(32), xMid0, xMid1)
	VPAND(maskHi, xMid0, xOut)

	VPADDQ(xMid1, xOut, xOut)
	VPADDQ(xLoLo, xOut, xOut)
}

func scalarMulAssignUint64AVX2() {
	TEXT("scalarMulAssignUint64AVX2", NOSPLIT, "func(v0 []uint64, c uint64, vOut []uint64)")
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	cv, cvSwap := YMM(), YMM()
	VPBROADCASTQ(NewParamAddr("c", 24), cv)
	shuffleForLoAVX2(cv, cvSwap)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)

	xOut := YMM()
	mul64LoAVX2(x0, cv, cvSwap, maskHi, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	c := GP64()
	Load(Param("c"), c)

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)

	IMULQ(c, y0)

	MOVQ(y0, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func scalarMulAddAssignUint64AVX2() {
	TEXT("scalarMulAddAssignUint64AVX2", NOSPLIT, "func(v0 []uint64, c uint64, vOut []uint64)")
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	cv, cvSwap := YMM(), YMM()
	VPBROADCASTQ(NewParamAddr("c", 24), cv)
	shuffleForLoAVX2(cv, cvSwap)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)

	mul64LoAVX2(x0, cv, cvSwap, maskHi, x0)
	VPADDQ(x0, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	c := GP64()
	Load(Param("c"), c)

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	yOut := GP64()
	MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)

	IMULQ(c, y0)
	ADDQ(y0, yOut)

	MOVQ(yOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func scalarMulSubAssignUint64AVX2() {
	TEXT("scalarMulSubAssignUint64AVX2", NOSPLIT, "func(v0 []uint64, c uint64, vOut []uint64)")
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	v0 := Load(Param("v0").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	cv, cvSwap := YMM(), YMM()
	VPBROADCASTQ(NewParamAddr("c", 24), cv)
	shuffleForLoAVX2(cv, cvSwap)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)

	mul64LoAVX2(x0, cv, cvSwap, maskHi, x0)
	VPSUBQ(x0, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	c := GP64()
	Load(Param("c"), c)

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	yOut := GP64()
	MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)

	IMULQ(c, y0)
	SUBQ(y0, yOut)

	MOVQ(yOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func elementWiseMulAssignUint64AVX2() {
	TEXT("elementWiseMulAssignUint64AVX2", NOSPLIT, "func(v0, v1, vOut []uint64)")
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	x1 := YMM()
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 8}, x1)

	x0Swap := YMM()
	shuffleForLoAVX2(x0, x0Swap)

	xOut := YMM()
	mul64LoAVX2(x1, x0, x0Swap, maskHi, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	y1 := GP64()
	MOVQ(Mem{Base: v1, Index: i, Scale: 8}, y1)

	IMULQ(y1, y0)

	MOVQ(y0, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func elementWiseMulAddAssignUint64AVX2() {
	TEXT("elementWiseMulAddAssignUint64AVX2", NOSPLIT, "func(v0, v1, vOut []uint64)")
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	x1 := YMM()
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 8}, x1)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)

	x0Swap := YMM()
	shuffleForLoAVX2(x0, x0Swap)

	mul64LoAVX2(x1, x0, x0Swap, maskHi, x1)
	VPADDQ(x1, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	y1 := GP64()
	MOVQ(Mem{Base: v1, Index: i, Scale: 8}, y1)
	yOut := GP64()
	MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)

	IMULQ(y1, y0)
	ADDQ(y0, yOut)

	MOVQ(yOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func elementWiseMulSubAssignUint64AVX2() {
	TEXT("elementWiseMulSubAssignUint64AVX2", NOSPLIT, "func(v0, v1, vOut []uint64)")
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
	vOut := Load(Param("vOut").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x0 := YMM()
	VMOVDQU(Mem{Base: v0, Index: i, Scale: 8}, x0)
	x1 := YMM()
	VMOVDQU(Mem{Base: v1, Index: i, Scale: 8}, x1)
	xOut := YMM()
	VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)

	x0Swap := YMM()
	shuffleForLoAVX2(x0, x0Swap)

	mul64LoAVX2(x1, x0, x0Swap, maskHi, x1)
	VPSUBQ(x1, xOut, xOut)

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y0 := GP64()
	MOVQ(Mem{Base: v0, Index: i, Scale: 8}, y0)
	y1 := GP64()
	MOVQ(Mem{Base: v1, Index: i, Scale: 8}, y1)
	yOut := GP64()
	MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)

	IMULQ(y1, y0)
	SUBQ(y0, yOut)

	MOVQ(yOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

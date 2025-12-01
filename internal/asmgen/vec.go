package main

import (
	"math"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

func VecConstants() {
	ConstData("MASK_HI", U64(math.MaxUint32<<32))
}

func AddSubToUint32AVX2(opType OpType) {
	switch opType {
	case OpAdd:
		TEXT("addToUint32AVX2", NOSPLIT, "func(vOut, v0, v1 []uint32)")
	case OpSub:
		TEXT("subToUint32AVX2", NOSPLIT, "func(vOut, v0, v1 []uint32)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
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
	switch opType {
	case OpAdd:
		VPADDD(x1, x0, xOut)
	case OpSub:
		VPSUBD(x1, x0, xOut)
	}

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

	switch opType {
	case OpAdd:
		ADDL(y1, y0)
	case OpSub:
		SUBL(y1, y0)
	}

	MOVL(y0, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func AddToUint64AVX2(opType OpType) {
	switch opType {
	case OpAdd:
		TEXT("addToUint64AVX2", NOSPLIT, "func(vOut, v0, v1 []uint64)")
	case OpSub:
		TEXT("subToUint64AVX2", NOSPLIT, "func(vOut, v0, v1 []uint64)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
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
	switch opType {
	case OpAdd:
		VPADDQ(x1, x0, xOut)
	case OpSub:
		VPSUBQ(x1, x0, xOut)
	}

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

	switch opType {
	case OpAdd:
		ADDQ(y1, y0)
	case OpSub:
		SUBQ(y1, y0)
	}

	MOVQ(y0, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func ScalarMulToUint32AVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("scalarMulToUint32AVX2", NOSPLIT, "func(vOut, v []uint32, c uint32)")
	case OpAdd:
		TEXT("scalarMulAddToUint32AVX2", NOSPLIT, "func(vOut, v []uint32, c uint32)")
	case OpSub:
		TEXT("scalarMulSubToUint32AVX2", NOSPLIT, "func(vOut, v []uint32, c uint32)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v := Load(Param("v").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(3), M)
	SHLQ(Imm(3), M)

	c32 := Load(Param("c"), GP32())
	c := YMM()
	VPBROADCASTD(NewParamAddr("c", 48), c)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x := YMM()
	VMOVDQU(Mem{Base: v, Index: i, Scale: 4}, x)

	xMul := YMM()
	VPMULLD(c, x, xMul)

	xOut := YMM()
	switch opType {
	case OpPure:
		xOut = xMul
	case OpAdd:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)
		VPADDD(xMul, xOut, xOut)
	case OpSub:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)
		VPSUBD(xMul, xOut, xOut)
	}

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(8), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y := GP32()
	MOVL(Mem{Base: v, Index: i, Scale: 4}, y)

	IMULL(c32, y)

	yOut := GP32()
	switch opType {
	case OpPure:
		yOut = y
	case OpAdd:
		MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)
		ADDL(y, yOut)
	case OpSub:
		MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)
		SUBL(y, yOut)
	}

	MOVL(yOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func MulToUint32AVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("mulToUint32AVX2", NOSPLIT, "func(vOut, v0, v1 []uint32)")
	case OpAdd:
		TEXT("mulAddToUint32AVX2", NOSPLIT, "func(vOut, v0, v1 []uint32)")
	case OpSub:
		TEXT("mulSubToUint32AVX2", NOSPLIT, "func(vOut, v0, v1 []uint32)")
	}
	Pragma("noescape")

	vOut := Load(Param("vOut").Base(), GP64())
	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
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

	xMul := YMM()
	VPMULLD(x1, x0, xMul)

	xOut := YMM()
	switch opType {
	case OpPure:
		xOut = xMul
	case OpAdd:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)
		VPADDD(xMul, xOut, xOut)
	case OpSub:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 4}, xOut)
		VPSUBD(xMul, xOut, xOut)
	}

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

	IMULL(y1, y0)

	yOut := GP32()
	switch opType {
	case OpPure:
		yOut = y0
	case OpAdd:
		MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)
		ADDL(y0, yOut)
	case OpSub:
		MOVL(Mem{Base: vOut, Index: i, Scale: 4}, yOut)
		SUBL(y0, yOut)
	}

	MOVL(yOut, Mem{Base: vOut, Index: i, Scale: 4})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func PrecomputeMul64LoAVX2(x, xSwap reg.VecVirtual) {
	VPSHUFD(Imm(0b10_11_00_01), x, xSwap)
}

func Mul64LoAVX2(x0, x1, x1Swap, maskHi, xOut reg.VecVirtual) {
	xLoLo := YMM()
	VPMULUDQ(x1, x0, xLoLo)

	xMid0, xMid1 := YMM(), YMM()
	VPMULLD(x1Swap, x0, xMid0)
	VPSLLQ(Imm(32), xMid0, xMid1)
	VPAND(maskHi, xMid0, xOut)

	VPADDQ(xMid1, xOut, xOut)
	VPADDQ(xLoLo, xOut, xOut)
}

func ScalarMulToUint64AVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("scalarMulToUint64AVX2", NOSPLIT, "func(vOut, v []uint64, c uint64)")
	case OpAdd:
		TEXT("scalarMulAddToUint64AVX2", NOSPLIT, "func(vOut, v []uint64, c uint64)")
	case OpSub:
		TEXT("scalarMulSubToUint64AVX2", NOSPLIT, "func(vOut, v []uint64, c uint64)")
	}
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	vOut := Load(Param("vOut").Base(), GP64())
	v := Load(Param("v").Base(), GP64())
	N := Load(Param("vOut").Len(), GP64())

	M := GP64()
	MOVQ(N, M)
	SHRQ(Imm(2), M)
	SHLQ(Imm(2), M)

	c64 := Load(Param("c"), GP64())
	c, cSwap := YMM(), YMM()
	VPBROADCASTQ(NewParamAddr("c", 48), c)
	PrecomputeMul64LoAVX2(c, cSwap)

	i := GP64()
	XORQ(i, i)
	JMP(LabelRef("loop_end"))
	Label("loop_body")

	x := YMM()
	VMOVDQU(Mem{Base: v, Index: i, Scale: 8}, x)

	xMul := YMM()
	Mul64LoAVX2(x, c, cSwap, maskHi, xMul)

	xOut := YMM()
	switch opType {
	case OpPure:
		xOut = xMul
	case OpAdd:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)
		VPADDQ(xMul, xOut, xOut)
	case OpSub:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)
		VPSUBQ(xMul, xOut, xOut)
	}

	VMOVDQU(xOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(4), i)

	Label("loop_end")
	CMPQ(i, M)
	JL(LabelRef("loop_body"))

	JMP(LabelRef("leftover_loop_end"))
	Label("leftover_loop_body")

	y := GP64()
	MOVQ(Mem{Base: v, Index: i, Scale: 8}, y)

	IMULQ(c64, y)

	yOut := GP64()
	switch opType {
	case OpPure:
		yOut = y
	case OpAdd:
		MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)
		ADDQ(y, yOut)
	case OpSub:
		MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)
		SUBQ(y, yOut)
	}

	MOVQ(yOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

func MulToUint64AVX2(opType OpType) {
	switch opType {
	case OpPure:
		TEXT("mulToUint64AVX2", NOSPLIT, "func(vOut, v0, v1 []uint64)")
	case OpAdd:
		TEXT("mulAddToUint64AVX2", NOSPLIT, "func(vOut, v0, v1 []uint64)")
	case OpSub:
		TEXT("mulSubToUint64AVX2", NOSPLIT, "func(vOut, v0, v1 []uint64)")
	}
	Pragma("noescape")

	maskHi := YMM()
	VPBROADCASTQ(NewDataAddr(NewStaticSymbol("MASK_HI"), 0), maskHi)

	vOut := Load(Param("vOut").Base(), GP64())
	v0 := Load(Param("v0").Base(), GP64())
	v1 := Load(Param("v1").Base(), GP64())
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

	x0Swap, xMul := YMM(), YMM()
	PrecomputeMul64LoAVX2(x0, x0Swap)
	Mul64LoAVX2(x1, x0, x0Swap, maskHi, xMul)

	xOut := YMM()
	switch opType {
	case OpPure:
		xOut = xMul
	case OpAdd:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)
		VPADDQ(xMul, xOut, xOut)
	case OpSub:
		VMOVDQU(Mem{Base: vOut, Index: i, Scale: 8}, xOut)
		VPSUBQ(xMul, xOut, xOut)
	}

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

	yOut := GP64()
	switch opType {
	case OpPure:
		yOut = y0
	case OpAdd:
		MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)
		ADDQ(y0, yOut)
	case OpSub:
		MOVQ(Mem{Base: vOut, Index: i, Scale: 8}, yOut)
		SUBQ(y0, yOut)
	}

	MOVQ(yOut, Mem{Base: vOut, Index: i, Scale: 8})

	ADDQ(Imm(1), i)

	Label("leftover_loop_end")
	CMPQ(i, N)
	JL(LabelRef("leftover_loop_body"))

	RET()
}

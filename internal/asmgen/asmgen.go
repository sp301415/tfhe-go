//go:generate go run . -fold -out ../../math/poly/asm_fold_amd64.s -stubs ../../math/poly/asm_fold_stub_amd64.go -pkg=poly
//go:generate go run . -fft -out ../../math/poly/asm_fft_amd64.s -stubs ../../math/poly/asm_fft_stub_amd64.go -pkg=poly
//go:generate go run . -vec_cmplx -out ../../math/poly/asm_vec_cmplx_amd64.s -stubs ../../math/poly/asm_vec_cmplx_stub_amd64.go -pkg=poly
//go:generate go run . -vec -out ../../math/vec/asm_vec_amd64.s -stubs ../../math/vec/asm_vec_stub_amd64.go -pkg=vec
//go:generate go run . -decompose -out ../../tfhe/asm_decompose_amd64.s -stubs ../../tfhe/asm_decompose_stub_amd64.go -pkg=tfhe
package main

import (
	"flag"

	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/buildtags"
)

type OpType int

const (
	OpPure OpType = iota
	OpAdd
	OpSub
)

var (
	fold     = flag.Bool("fold", false, "asm_fold_amd64.s")
	fft      = flag.Bool("fft", false, "asm_fft_amd64.s")
	vecCmplx = flag.Bool("vec_cmplx", false, "asm_vec_cmplx_amd64.s")

	vec = flag.Bool("vec", false, "asm_vec_amd64.s")

	decompose = flag.Bool("decompose", false, "asm_decompose_amd64.s")
)

func main() {
	flag.Parse()

	Constraint(buildtags.Term("amd64"))
	Constraint(buildtags.Not("purego"))

	if *fold {
		FoldConstants()

		FoldPolyToUint32AVX2()
		foldPolyToUint64AVX2()

		FloatModQInPlaceAVX2()

		UnfoldPolyToUint32AVX2(OpPure)
		UnfoldPolyToUint32AVX2(OpAdd)
		UnfoldPolyToUint32AVX2(OpSub)

		UnfoldPolyToUint64AVX2(OpPure)
		UnfoldPolyToUint64AVX2(OpAdd)
		UnfoldPolyToUint64AVX2(OpSub)

	}

	if *fft {
		FwdFFTInPlaceAVX2()
		InvFFTInPlaceAVX2()
	}

	if *vecCmplx {
		AddSubCmplxToAVX2(OpAdd)
		AddSubCmplxToAVX2(OpSub)

		NegCmplxToAVX2()

		FloatMulCmplxToAVX2(OpPure)
		FloatMulCmplxToAVX2(OpAdd)
		FloatMulCmplxToAVX2(OpSub)

		CmplxMulCmplxToAVX2(OpPure)
		CmplxMulCmplxToAVX2(OpAdd)
		CmplxMulCmplxToAVX2(OpSub)

		MulCmplxToAVX2(OpPure)
		MulCmplxToAVX2(OpAdd)
		MulCmplxToAVX2(OpSub)
	}

	if *vec {
		VecConstants()

		AddSubToUint32AVX2(OpAdd)
		AddSubToUint32AVX2(OpSub)

		AddToUint64AVX2(OpAdd)
		AddToUint64AVX2(OpSub)

		ScalarMulToUint32AVX2(OpPure)
		ScalarMulToUint32AVX2(OpAdd)
		ScalarMulToUint32AVX2(OpSub)

		ScalarMulToUint64AVX2(OpPure)
		ScalarMulToUint64AVX2(OpAdd)
		ScalarMulToUint64AVX2(OpSub)

		MulToUint32AVX2(OpPure)
		MulToUint32AVX2(OpAdd)
		MulToUint32AVX2(OpSub)

		MulToUint64AVX2(OpPure)
		MulToUint64AVX2(OpAdd)
		MulToUint64AVX2(OpSub)
	}

	if *decompose {
		DecomposeConstants()

		DecomposePolyToUint32AVX2()
		DecomposePolyToUint64AVX2()
	}

	Generate()
}

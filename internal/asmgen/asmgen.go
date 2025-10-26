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
		foldConstants()

		foldPolyToUint32AVX2()
		foldPolyToUint64AVX2()

		floatModInPlaceAVX2()

		unfoldPolyToUint32AVX2()
		unfoldPolyToUint64AVX2()

		unfoldPolyAddToUint32AVX2()
		unfoldPolyAddToUint64AVX2()

		unfoldPolySubToUint32AVX2()
		unfoldPolySubToUint64AVX2()

	}

	if *fft {
		fftInPlaceAVX2()
		ifftInPlaceAVX2()
	}

	if *vecCmplx {
		addCmplxToAVX2()
		subCmplxToAVX2()
		negCmplxToAVX2()

		floatMulCmplxToAVX2()
		floatMulAddCmplxToAVX2()
		floatMulSubCmplxToAVX2()

		cmplxMulCmplxToAVX2()
		cmplxMulAddCmplxToAVX2()
		cmplxMulSubCmplxToAVX2()

		mulCmplxToAVX2()
		mulAddCmplxToAVX2()
		mulSubCmplxToAVX2()
	}

	if *vec {
		vecConstants()

		addToUint32AVX2()
		addToUint64AVX2()

		subToUint32AVX2()
		subToUint64AVX2()

		scalarMulToUint32AVX2()
		scalarMulToUint64AVX2()

		scalarMulAddToUint32AVX2()
		scalarMulAddToUint64AVX2()

		scalarMulSubToUint32AVX2()
		scalarMulSubToUint64AVX2()

		mulToUint32AVX2()
		mulToUint64AVX2()

		mulAddToUint32AVX2()
		mulAddToUint64AVX2()

		mulSubToUint32AVX2()
		mulSubToUint64AVX2()
	}

	if *decompose {
		decomposeConstants()

		decomposePolyToUint32AVX2()
		decomposePolyToUint64AVX2()
	}

	Generate()
}

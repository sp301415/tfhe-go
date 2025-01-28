//go:generate go run . -convert -out ../../math/poly/asm_convert_amd64.s -stubs ../../math/poly/asm_convert_stub_amd64.go -pkg=poly
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
	convert  = flag.Bool("convert", false, "asm_convert_amd64.s")
	fft      = flag.Bool("fft", false, "asm_fft_amd64.s")
	vecCmplx = flag.Bool("vec_cmplx", false, "asm_vec_cmplx_amd64.s")

	vec = flag.Bool("vec", false, "asm_vec_amd64.s")

	decompose = flag.Bool("decompose", false, "asm_decompose_amd64.s")
)

func main() {
	flag.Parse()

	Constraint(buildtags.Term("amd64"))
	Constraint(buildtags.Not("purego"))

	if *convert {
		convertConstants()

		convertPolyToFourierPolyAssignUint32AVX2()
		convertPolyToFourierPolyAssignUint64AVX2()

		floatModQInPlaceAVX2()

		convertFourierPolyToPolyAssignUint32AVX2()
		convertFourierPolyToPolyAssignUint64AVX2()

		convertFourierPolyToPolyAddAssignUint32AVX2()
		convertFourierPolyToPolyAddAssignUint64AVX2()

		convertFourierPolyToPolySubAssignUint32AVX2()
		convertFourierPolyToPolySubAssignUint64AVX2()

	}

	if *fft {
		fftInPlaceAVX2()
		ifftInPlaceAVX2()
	}

	if *vecCmplx {
		addCmplxAssignAVX2()
		subCmplxAssignAVX2()
		negCmplxAssignAVX2()

		floatMulCmplxAssignAVX2()
		floatMulAddCmplxAssignAVX2()
		floatMulSubCmplxAssignAVX2()

		cmplxMulCmplxAssignAVX2()
		cmplxMulAddCmplxAssignAVX2()
		cmplxMulSubCmplxAssignAVX2()

		elementWiseMulCmplxAssignAVX2()
		elementWiseMulAddCmplxAssignAVX2()
		elementWiseMulSubCmplxAssignAVX2()
	}

	if *vec {
		addAssignUint32AVX2()
		addAssignUint64AVX2()

		subAssignUint32AVX2()
		subAssignUint64AVX2()

		scalarMulAssignUint32AVX2()
		scalarMulAssignUint64AVX2()

		scalarMulAddAssignUint32AVX2()
		scalarMulAddAssignUint64AVX2()

		scalarMulSubAssignUint32AVX2()
		scalarMulSubAssignUint64AVX2()

		elementWiseMulAssignUint32AVX2()
		elementWiseMulAssignUint64AVX2()

		elementWiseMulAddAssignUint32AVX2()
		elementWiseMulAddAssignUint64AVX2()

		elementWiseMulSubAssignUint32AVX2()
		elementWiseMulSubAssignUint64AVX2()
	}

	if *decompose {
		decomposeConstants()

		decomposePolyAssignUint32AVX2()
		decomposePolyAssignUint64AVX2()
	}

	Generate()
}

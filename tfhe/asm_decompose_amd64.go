//go:build amd64 && !purego

package tfhe

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/sys/cpu"
)

// decomposePolyTo decomposes p with respect to gadgetParams and writes it to dcmpOut.
func decomposePolyTo[T TorusInt](dcmpOut []poly.Poly[T], p poly.Poly[T], gadgetParams GadgetParameters[T]) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			decomposePolyToUint32AVX2(
				*(*[][]uint32)(unsafe.Pointer(&dcmpOut)),
				*(*[]uint32)(unsafe.Pointer(&p)),
				uint32(gadgetParams.base),
				uint32(gadgetParams.logBase),
				uint32(gadgetParams.LogLastBaseQ()),
			)
			return
		case uint64:
			decomposePolyToUint64AVX2(
				*(*[][]uint64)(unsafe.Pointer(&dcmpOut)),
				*(*[]uint64)(unsafe.Pointer(&p)),
				uint64(gadgetParams.base),
				uint64(gadgetParams.logBase),
				uint64(gadgetParams.LogLastBaseQ()),
			)
			return
		}
	}

	logLastBaseQ := gadgetParams.LogLastBaseQ()
	for i := 0; i < p.Rank(); i++ {
		c := num.DivRoundBits(p.Coeffs[i], logLastBaseQ)
		for j := gadgetParams.level - 1; j >= 1; j-- {
			dcmpOut[j].Coeffs[i] = c & (gadgetParams.base - 1)
			c >>= gadgetParams.logBase
			c += dcmpOut[j].Coeffs[i] >> (gadgetParams.logBase - 1)
			dcmpOut[j].Coeffs[i] -= (dcmpOut[j].Coeffs[i] & (gadgetParams.base >> 1)) << 1
		}
		dcmpOut[0].Coeffs[i] = c & (gadgetParams.base - 1)
		dcmpOut[0].Coeffs[i] -= (dcmpOut[0].Coeffs[i] & (gadgetParams.base >> 1)) << 1
	}
}

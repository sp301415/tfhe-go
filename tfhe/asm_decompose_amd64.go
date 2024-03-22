//go:build amd64 && !purego

package tfhe

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/sys/cpu"
)

func decomposePolyAssignUint32AVX2(p []uint32, base uint32, baseLog uint32, lastScaledBaseLog uint32, decomposedOut [][]uint32)
func decomposePolyAssignUint64AVX2(p []uint64, base uint64, baseLog uint64, lastScaledBaseLog uint64, decomposedOut [][]uint64)

// decomposePolyAssign decomposes p with respect to gadgetParams and writes it to decomposedOut.
func decomposePolyAssign[T TorusInt](p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			decomposePolyAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&p)),
				uint32(gadgetParams.base),
				uint32(gadgetParams.baseLog),
				uint32(gadgetParams.scaledBasesLog[gadgetParams.level-1]),
				*(*[][]uint32)(unsafe.Pointer(&decomposedOut)),
			)
			return
		case uint64:
			decomposePolyAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&p)),
				uint64(gadgetParams.base),
				uint64(gadgetParams.baseLog),
				uint64(gadgetParams.scaledBasesLog[gadgetParams.level-1]),
				*(*[][]uint64)(unsafe.Pointer(&decomposedOut)),
			)
			return
		}
	}

	lastScaledBaseLog := gadgetParams.scaledBasesLog[gadgetParams.level-1]
	for i := 0; i < p.Degree(); i++ {
		c := num.RoundRatioBits(p.Coeffs[i], lastScaledBaseLog)
		for j := gadgetParams.level - 1; j >= 1; j-- {
			decomposedOut[j].Coeffs[i] = c & (gadgetParams.base - 1)
			c >>= gadgetParams.baseLog
			c += decomposedOut[j].Coeffs[i] >> (gadgetParams.baseLog - 1)
			decomposedOut[j].Coeffs[i] -= (decomposedOut[j].Coeffs[i] & (gadgetParams.base >> 1)) << 1
		}
		decomposedOut[0].Coeffs[i] = c & (gadgetParams.base - 1)
		decomposedOut[0].Coeffs[i] -= (decomposedOut[0].Coeffs[i] & (gadgetParams.base >> 1)) << 1
	}
}

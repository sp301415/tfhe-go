//go:build amd64 && !purego

package tfhe

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/sys/cpu"
)

func decomposeUint32PolyAssignAVX2(p []uint32, base uint32, baseLog uint32, lastScaledBaseLog uint32, d [][]uint32)
func decomposeUint64PolyAssignAVX2(p []uint64, base uint64, baseLog uint64, lastScaledBaseLog uint64, d [][]uint64)

// decomposePolyAssign decomposes p with respect to decompParams, and writes it to decomposedOut.
func decomposePolyAssign[T Tint](p poly.Poly[T], decompParams DecompositionParameters[T], decomposedOut []poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			decomposeUint32PolyAssignAVX2(
				*(*[]uint32)(unsafe.Pointer(&p)),
				uint32(decompParams.base),
				uint32(decompParams.baseLog),
				uint32(decompParams.scaledBasesLog[decompParams.level-1]),
				*(*[][]uint32)(unsafe.Pointer(&decomposedOut)),
			)
		case uint64:
			decomposeUint64PolyAssignAVX2(
				*(*[]uint64)(unsafe.Pointer(&p)),
				uint64(decompParams.base),
				uint64(decompParams.baseLog),
				uint64(decompParams.scaledBasesLog[decompParams.level-1]),
				*(*[][]uint64)(unsafe.Pointer(&decomposedOut)),
			)
		}
		return
	}

	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	for i := 0; i < p.Degree(); i++ {
		c := num.RoundRatioBits(p.Coeffs[i], lastScaledBaseLog)
		for j := decompParams.level - 1; j >= 1; j-- {
			decomposedOut[j].Coeffs[i] = c & decompParams.baseMask
			c >>= decompParams.baseLog
			c += decomposedOut[j].Coeffs[i] >> decompParams.baseLogMinusOne
			decomposedOut[j].Coeffs[i] -= (decomposedOut[j].Coeffs[i] & decompParams.baseHalf) << 1
		}
		decomposedOut[0].Coeffs[i] = c & decompParams.baseMask
		decomposedOut[0].Coeffs[i] -= (decomposedOut[0].Coeffs[i] & decompParams.baseHalf) << 1
	}
}

//go:build !amd64

package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// DecomposePolyAssign decomposes p with respect to decompParams, and writes it to decompOut.
func DecomposePolyAssign[T Tint](p poly.Poly[T], decompParams DecompositionParameters[T], decomposedOut []poly.Poly[T]) {
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

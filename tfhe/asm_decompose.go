//go:build !(amd64 && !purego)

package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// decomposePolyAssign decomposes p with respect to gadgetParams, and writes it to decomposedOut.
func decomposePolyAssign[T Tint](p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.Poly[T]) {
	lastScaledBaseLog := gadgetParams.scaledBasesLog[gadgetParams.level-1]
	for i := 0; i < p.Degree(); i++ {
		c := num.RoundRatioBits(p.Coeffs[i], lastScaledBaseLog)
		for j := gadgetParams.level - 1; j >= 1; j-- {
			decomposedOut[j].Coeffs[i] = c & gadgetParams.baseMask
			c >>= gadgetParams.baseLog
			c += decomposedOut[j].Coeffs[i] >> gadgetParams.baseLogMinusOne
			decomposedOut[j].Coeffs[i] -= (decomposedOut[j].Coeffs[i] & gadgetParams.baseHalf) << 1
		}
		decomposedOut[0].Coeffs[i] = c & gadgetParams.baseMask
		decomposedOut[0].Coeffs[i] -= (decomposedOut[0].Coeffs[i] & gadgetParams.baseHalf) << 1
	}
}
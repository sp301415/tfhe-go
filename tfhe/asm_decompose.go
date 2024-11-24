//go:build !(amd64 && !purego)

package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// decomposePolyAssign decomposes p with respect to gadgetParams and writes it to decomposedOut.
func decomposePolyAssign[T TorusInt](p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.Poly[T]) {
	logLastBaseQ := gadgetParams.LogLastBaseQ()
	for i := 0; i < p.Degree(); i++ {
		c := num.DivRoundBits(p.Coeffs[i], logLastBaseQ)
		for j := gadgetParams.level - 1; j >= 1; j-- {
			decomposedOut[j].Coeffs[i] = c & (gadgetParams.base - 1)
			c >>= gadgetParams.logBase
			c += decomposedOut[j].Coeffs[i] >> (gadgetParams.logBase - 1)
			decomposedOut[j].Coeffs[i] -= (decomposedOut[j].Coeffs[i] & (gadgetParams.base >> 1)) << 1
		}
		decomposedOut[0].Coeffs[i] = c & (gadgetParams.base - 1)
		decomposedOut[0].Coeffs[i] -= (decomposedOut[0].Coeffs[i] & (gadgetParams.base >> 1)) << 1
	}
}

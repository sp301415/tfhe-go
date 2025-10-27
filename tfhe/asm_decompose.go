//go:build !(amd64 && !purego)

package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// decomposePolyTo decomposes p with respect to gadgetParams and writes it to dcmpOut.
func decomposePolyTo[T TorusInt](dcmpOut []poly.Poly[T], p poly.Poly[T], gadgetParams GadgetParameters[T]) {
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

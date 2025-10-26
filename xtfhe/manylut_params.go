package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ManyLUTParametersLiteral is a structure for PBSManyLUT Parameters.
//
// PolyRank does not equal LUTSize.
type ManyLUTParametersLiteral[T tfhe.TorusInt] struct {
	// BaseParams is a base parameters for this ManyLUTParametersLiteral.
	BaseParams tfhe.ParametersLiteral[T]

	// LUTCount is the number of LUTs that can be evaluated at once.
	// LUTCount must be a power of 2.
	LUTCount int
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
func (p ManyLUTParametersLiteral[T]) Compile() ManyLUTParameters[T] {
	baseParams := p.BaseParams.Compile()

	switch {
	case baseParams.PolyRank() != baseParams.LUTSize():
		panic("Compile: PolyRank does not equal LUTSize")
	case !num.IsPowerOfTwo(p.LUTCount):
		panic("Compile: lutCount not power of two")
	}

	return ManyLUTParameters[T]{
		baseParams: baseParams,

		lutCount:    p.LUTCount,
		logLUTCount: num.Log2(p.LUTCount),
	}
}

// ManyLUTParameters is a parameter set for PBSManyLUT.
type ManyLUTParameters[T tfhe.TorusInt] struct {
	// baseParams is a base parameters for this ManyLUTParameters.
	baseParams tfhe.Parameters[T]

	// LUTCount is the number of LUTs that can be evaluated at once.
	// LUTCount must be a power of 2.
	lutCount int
	// LogLUTCount equals log(LUTCount).
	logLUTCount int
}

// BaseParams returns the base parameters for this ManyLUTParameters.
func (p ManyLUTParameters[T]) BaseParams() tfhe.Parameters[T] {
	return p.baseParams
}

// LUTCount returns the number of LUTs that can be evaluated at once.
func (p ManyLUTParameters[T]) LUTCount() int {
	return p.lutCount
}

// LogLUTCount returns log(LUTCount).
func (p ManyLUTParameters[T]) LogLUTCount() int {
	return p.logLUTCount
}

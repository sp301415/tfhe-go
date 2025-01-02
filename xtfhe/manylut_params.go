package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ManyLUTParametersLiteral is a structure for PBSManyLUT Parameters.
//
// PolyDegree must equal LookUpTableSize.
type ManyLUTParametersLiteral[T tfhe.TorusInt] struct {
	// BaseParametersLiteral is a base parameter set for this ManyLUTParametersLiteral.
	BaseParametersLiteral tfhe.ParametersLiteral[T]

	// LUTCount is the number of LUTs that can be evaluated at once.
	// LUTCount must be a power of 2.
	LUTCount int
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
func (p ManyLUTParametersLiteral[T]) Compile() ManyLUTParameters[T] {
	switch {
	case p.BaseParametersLiteral.PolyDegree != p.BaseParametersLiteral.LookUpTableSize:
		panic("PolyDegree must equal LookUpTableSize")
	case !num.IsPowerOfTwo(p.LUTCount):
		panic("lutCount not power of two")
	}

	return ManyLUTParameters[T]{
		baseParameters: p.BaseParametersLiteral.Compile(),

		lutCount:    p.LUTCount,
		logLUTCount: num.Log2(p.LUTCount),
	}
}

// ManyLUTParameters is a parameter set for PBSManyLUT.
type ManyLUTParameters[T tfhe.TorusInt] struct {
	// baseParameters is a base parameter set for this ManyLUTParameters.
	baseParameters tfhe.Parameters[T]

	// LUTCount is the number of LUTs that can be evaluated at once.
	// LUTCount must be a power of 2.
	lutCount int
	// LogLUTCount equals log(LUTCount).
	logLUTCount int
}

// BaseParameters returns the base parameter set for this ManyLUTParameters.
func (p ManyLUTParameters[T]) BaseParameters() tfhe.Parameters[T] {
	return p.baseParameters
}

// LUTCount returns the number of LUTs that can be evaluated at once.
func (p ManyLUTParameters[T]) LUTCount() int {
	return p.lutCount
}

// LogLUTCount returns log(LUTCount).
func (p ManyLUTParameters[T]) LogLUTCount() int {
	return p.logLUTCount
}

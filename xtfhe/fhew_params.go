package xtfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FHEWParametersLiteral is a structure for FHEW Parameters.
//
// BlockSize must be 1, and PolyDegree does not equal LookUpTableSize.
type FHEWParametersLiteral[T tfhe.TorusInt] struct {
	// BaseParametersLiteral is a base parameters for this FHEWParametersLiteral.
	BaseParametersLiteral tfhe.ParametersLiteral[T]

	// SecretKeyStdDev is the standard deviation of the secret key.
	// Must be smaller than [poly.ShortPolyBound] / 8Q.
	SecretKeyStdDev float64

	// WindowSize is the window size for the FHEW blind rotation.
	WindowSize int
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
func (p FHEWParametersLiteral[T]) Compile() FHEWParameters[T] {
	baseParameters := p.BaseParametersLiteral.Compile()

	logQ := float64(baseParameters.LogQ())
	logTailCut := math.Log2(GaussianTailCut)
	switch {
	case baseParameters.BlockSize() != 1:
		panic("BlockSize not 1")
	case baseParameters.PolyDegree() != baseParameters.LookUpTableSize():
		panic("PolyDegree does not equal LookUpTableSize")
	case p.SecretKeyStdDev <= 0:
		panic("SecretKeyStdDev smaller than or equal to 0")
	case math.Log2(p.SecretKeyStdDev)+logQ+logTailCut > poly.ShortLogBound:
		panic("SecretKeyStdDev too large")
	case p.WindowSize < 0:
		panic("WindowSize smaller than 0")
	}

	return FHEWParameters[T]{
		baseParameters: baseParameters,

		secretKeyStdDev: p.SecretKeyStdDev,
		windowSize:      p.WindowSize,
	}
}

// FHEWParameters are read-only, compiled parameters for FHEW.
type FHEWParameters[T tfhe.TorusInt] struct {
	// BaseParameters is a base parameters for this FHEWParameters.
	baseParameters tfhe.Parameters[T]

	// SecretKeyStdDev is the standard deviation of the secret key.
	// Must be smaller than [poly.ShortPolyBound] / 8Q.
	secretKeyStdDev float64

	// WindowSize is the window size for the FHEW blind rotation.
	windowSize int
}

// BaseParameters returns the base parameters for this FHEWParameters.
func (p FHEWParameters[T]) BaseParameters() tfhe.Parameters[T] {
	return p.baseParameters
}

// SecretKeyStdDev returns the standard deviation of the secret key.
//
// This is a normlized standard deviation.
// For actual sampling, use [FHEWParameters.SecretKeyStdDevQ].
func (p FHEWParameters[T]) SecretKeyStdDev() float64 {
	return p.secretKeyStdDev
}

// SecretKeyStdDevQ returns SecretKeyStdDev * Q
func (p FHEWParameters[T]) SecretKeyStdDevQ() float64 {
	return p.secretKeyStdDev * math.Exp2(float64(p.baseParameters.LogQ()))
}

// WindowSize returns the window size for the FHEW blind rotation.
func (p FHEWParameters[T]) WindowSize() int {
	return p.windowSize
}

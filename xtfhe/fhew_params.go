package xtfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FHEWParametersLiteral is a structure for FHEW Parameters.
//
// BlockSize must be 1, and PolyRank does not equal LUTSize.
type FHEWParametersLiteral[T tfhe.TorusInt] struct {
	// BaseParams is a base parameters for this FHEWParametersLiteral.
	BaseParams tfhe.ParametersLiteral[T]

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
	baseParams := p.BaseParams.Compile()

	logQ := float64(baseParams.LogQ())
	logTailCut := math.Log2(GaussianTailCut)
	switch {
	case baseParams.BlockSize() != 1:
		panic("Compile: BlockSize not 1")
	case baseParams.PolyRank() != baseParams.LUTSize():
		panic("Compile: PolyRank does not equal LUTSize")
	case p.SecretKeyStdDev <= 0:
		panic("Compile: SecretKeyStdDev smaller than or equal to 0")
	case math.Log2(p.SecretKeyStdDev)+logQ+logTailCut > poly.ShortLogBound:
		panic("Compile: SecretKeyStdDev too large")
	case p.WindowSize < 0:
		panic("Compile: WindowSize smaller than 0")
	}

	return FHEWParameters[T]{
		baseParams: baseParams,

		secretKeyStdDev: p.SecretKeyStdDev,
		windowSize:      p.WindowSize,
	}
}

// FHEWParameters are read-only, compiled parameters for FHEW.
type FHEWParameters[T tfhe.TorusInt] struct {
	// BaseParams is a base parameters for this FHEWParameters.
	baseParams tfhe.Parameters[T]

	// SecretKeyStdDev is the standard deviation of the secret key.
	// Must be smaller than [poly.ShortPolyBound] / 8Q.
	secretKeyStdDev float64

	// WindowSize is the window size for the FHEW blind rotation.
	windowSize int
}

// BaseParams returns the base parameters for this FHEWParameters.
func (p FHEWParameters[T]) BaseParams() tfhe.Parameters[T] {
	return p.baseParams
}

// SecretKeyStdDev returns the standard deviation of the secret key.
//
// This is a normalized standard deviation.
// For actual sampling, use [FHEWParameters.SecretKeyStdDevQ].
func (p FHEWParameters[T]) SecretKeyStdDev() float64 {
	return p.secretKeyStdDev
}

// SecretKeyStdDevQ returns SecretKeyStdDev * Q
func (p FHEWParameters[T]) SecretKeyStdDevQ() float64 {
	return p.secretKeyStdDev * math.Exp2(float64(p.baseParams.LogQ()))
}

// WindowSize returns the window size for the FHEW blind rotation.
func (p FHEWParameters[T]) WindowSize() int {
	return p.windowSize
}

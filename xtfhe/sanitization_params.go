package xtfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// SanitizationParametersLiteral is a structure for TFHE Sanitization Parameters.
type SanitizationParametersLiteral[T tfhe.TorusInt] struct {
	// BaseParams is a base parameters for this SanitizationParametersLiteral.
	BaseParams tfhe.ParametersLiteral[T]

	// RandSigma is the standard deviation used for
	// Discrete Gaussian sampling in Rand operation.
	RandSigma float64
	// RandTau is the standard deviation used for
	// Rounded Gaussian sampling in Rand operation.
	RandTau float64

	// LinEvalSigma is the standard deviation used for
	// Discrete Gaussian sampling in LinEval operation.
	LinEvalSigma float64
	// LinEvalTau is the standard deviation used for
	// Rounded Gaussian sampling in LinEval operation.
	LinEvalTau float64
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
func (p SanitizationParametersLiteral[T]) Compile() SanitizationParameters[T] {
	baseParameters := p.BaseParams.Compile()

	switch {
	case baseParameters.GLWERank() != 1:
		panic("GLWERank not 1")
	case baseParameters.PolyRank() != baseParameters.LUTSize():
		panic("PolyRank does not equal LUTSize")
	case baseParameters.BootstrapOrder() != tfhe.OrderKeySwitchBlindRotate:
		panic("BootstrapOrder not OrderKeySwitchBlindRotate")
	case p.RandSigma <= 0:
		panic("RandSigma smaller than zero")
	case p.RandTau <= 0:
		panic("RandTau smaller than zero")
	case p.LinEvalSigma <= 0:
		panic("LinEvalSigma smaller than zero")
	case p.LinEvalTau <= 0:
		panic("LinEvalTau smaller than zero")
	}

	return SanitizationParameters[T]{
		baseParams: baseParameters,

		floatQ: math.Exp2(float64(num.SizeT[T]())),

		randSigma: p.RandSigma,
		randTau:   p.RandTau,

		linEvalSigma: p.LinEvalSigma,
		linEvalTau:   p.LinEvalTau,
	}
}

// SanitizationParameters is a parameter set for TFHE Sanitization.
type SanitizationParameters[T tfhe.TorusInt] struct {
	// baseParams is a base parameters for this SanitizationParameters.
	baseParams tfhe.Parameters[T]

	// floatQ is the value of Q as float64.
	floatQ float64

	// RandSigma is the standard deviation used for
	// Discrete Gaussian sampling in Rand operation.
	randSigma float64
	// RandTau is the standard deviation used for
	// Rounded Gaussian sampling in Rand operation.
	randTau float64

	// LinEvalSigma is the standard deviation used for
	// Discrete Gaussian sampling in LinEval operation.
	linEvalSigma float64
	// LinEvalTau is the standard deviation used for
	// Rounded Gaussian sampling in LinEval operation.
	linEvalTau float64
}

// BaseParams returns the base parameters for this SanitizationParameters.
func (p SanitizationParameters[T]) BaseParams() tfhe.Parameters[T] {
	return p.baseParams
}

// RandSigma returns the standard deviation used for
// Discrete Gaussian sampling in Rand operation.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.RandSigmaQ].
func (p SanitizationParameters[T]) RandSigma() float64 {
	return p.randSigma
}

// RandSigmaQ returns RandSigma * Q.
func (p SanitizationParameters[T]) RandSigmaQ() float64 {
	return p.randSigma * p.floatQ
}

// RandTau returns the standard deviation used for
// Rounded Gaussian sampling in Rand operation.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.RandTauQ].
func (p SanitizationParameters[T]) RandTau() float64 {
	return p.randTau
}

// RandTauQ returns RandTau * Q.
func (p SanitizationParameters[T]) RandTauQ() float64 {
	return p.randTau * p.floatQ
}

// LinEvalSigma returns the standard deviation used for
// Discrete Gaussian sampling in LinEval operation.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.LinEvalSigmaQ].
func (p SanitizationParameters[T]) LinEvalSigma() float64 {
	return p.linEvalSigma
}

// LinEvalSigmaQ returns LinEvalSigma * Q.
func (p SanitizationParameters[T]) LinEvalSigmaQ() float64 {
	return p.linEvalSigma * p.floatQ
}

// LinEvalTau returns the standard deviation used for
// Rounded Gaussian sampling in LinEval operation.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.LinEvalTauQ].
func (p SanitizationParameters[T]) LinEvalTau() float64 {
	return p.linEvalTau
}

// LinEvalTauQ returns LinEvalTau * Q.
func (p SanitizationParameters[T]) LinEvalTauQ() float64 {
	return p.linEvalTau * p.floatQ
}

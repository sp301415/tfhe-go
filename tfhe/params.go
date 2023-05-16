package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
)

// Tint represents the integer in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type Tint interface {
	uint32 | uint64
}

// DecompositionParameters is a Parameter for gadget decomposition,
// used in GSW and GGSW encryptions.
type DecompositionParametersLiteral[T Tint] struct {
	// Base is a base of gadget. It must be power of two.
	Base T
	// Level is a length of gadget.
	Level int
}

// Compile transforms DecompositionParametersLiteral to read-only DecompositionParameters.
// If Level = 0, it still compiles, but you will have runtime panics when trying to use this parameter.
// If there is any invalid parameter in the literal, it panics.
func (p DecompositionParametersLiteral[T]) Compile() DecompositionParameters[T] {
	if p.Level == 0 {
		return DecompositionParameters[T]{}
	}

	switch {
	case !num.IsPowerOfTwo(p.Base):
		panic("base not power of two")
	case p.Level <= 0:
		panic("Level smaller than zero")
	case num.SizeT[T]() <= num.Log2(p.Base)+p.Level:
		panic("Base * Level larger than Q")
	}

	baseLog := num.Log2(p.Base)
	scaledBasesLog := make([]int, p.Level)
	for i := range scaledBasesLog {
		scaledBasesLog[i] = num.SizeT[T]() - (i+1)*baseLog
	}

	return DecompositionParameters[T]{
		base:           p.Base,
		baseLog:        baseLog,
		maxBits:        num.SizeT[T](),
		level:          p.Level,
		scaledBasesLog: scaledBasesLog,
	}
}

// DecompositionParameters is a read-only, compiled parameters based on DecompositionParametersLiteral.
type DecompositionParameters[T Tint] struct {
	// Base is a base of gadget. It must be power of two.
	base T
	// BaseLog equals log(Base).
	baseLog int
	// MaxBits equals bit length of T.
	maxBits int
	// Level is a length of gadget.
	level int
	// scaledBasesLog holds the log of scaled gadget: Log(Q / B^l) for l = 1 ~ Level.
	scaledBasesLog []int
}

// Base is a base of gadget. It must be power of two.
func (p DecompositionParameters[T]) Base() T {
	return p.base
}

// BaseLog equals log(Base).
func (p DecompositionParameters[T]) BaseLog() int {
	return p.baseLog
}

// Level is a length of gadget.
func (p DecompositionParameters[T]) Level() int {
	return p.level
}

// ScaledBase returns Q / Base^(i+1) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use FirstScaledBase() and LastScaledBase().
func (p DecompositionParameters[T]) ScaledBase(i int) T {
	return T(1 << p.scaledBasesLog[i])
}

// FirstScaledBase returns Q / Base.
func (p DecompositionParameters[T]) FirstScaledBase() T {
	return p.ScaledBase(0)
}

// LastScaledBase returns Q / Base^Level.
func (p DecompositionParameters[T]) LastScaledBase() T {
	return p.ScaledBase(p.level - 1)
}

// ScaledBaseLog returns log(Q / Base^(i+1)) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use FirstScaledBaseLog() and LastScaledBaseLog().
func (p DecompositionParameters[T]) ScaledBaseLog(i int) int {
	return p.scaledBasesLog[i]
}

// FirstScaledBaseLog returns log(Q / Base).
func (p DecompositionParameters[T]) FirstScaledBaseLog() int {
	return p.ScaledBaseLog(0)
}

// LastScaledBaseLog returns log(Q / Base^Level).
func (p DecompositionParameters[T]) LastScaledBaseLog() int {
	return p.ScaledBaseLog(p.level - 1)
}

// Decompose decomposes x.
// This function calculates d_i, where x = sum_{i=1}^level d_i * (Q / Base^i).
func (p DecompositionParameters[T]) Decompose(x T) []T {
	d := make([]T, p.level)
	p.DecomposeInPlace(x, d)
	return d
}

// DecomposeInPlace decomposes x and writes it to d.
// Length of d should be Level.
func (p DecompositionParameters[T]) DecomposeInPlace(x T, d []T) {
	x = num.RoundRatioBits(x, p.scaledBasesLog[p.level-1])
	for i := range d {
		res := x & (p.base - 1)
		x >>= p.baseLog
		carry := ((res - 1) | x) & res
		carry >>= p.baseLog - 1
		x += carry
		res -= carry << p.baseLog
		d[p.level-i-1] = res
	}
}

// DecomposePoly decomposes polynomial x.
// This function calculates polynomials d_i, where x = sum_{i=1}^level d_i * (Q / Base^i).
func (p DecompositionParameters[T]) DecomposePoly(x poly.Poly[T]) []poly.Poly[T] {
	d := make([]poly.Poly[T], p.level)
	for i := range d {
		d[i] = poly.New[T](x.Degree())
	}
	p.DecomposePolyInPlace(x, d)
	return d
}

// DecomposePolyInPlace decomposes polynomial x, and writes it to d.
// Length of d should be Level, each polynomial having same degree as x.
func (p DecompositionParameters[T]) DecomposePolyInPlace(x poly.Poly[T], d []poly.Poly[T]) {
	for i := range x.Coeffs {
		c := num.RoundRatioBits(x.Coeffs[i], p.scaledBasesLog[p.level-1])
		for j := range d {
			res := c & (p.base - 1)
			c >>= p.baseLog
			carry := ((res - 1) | c) & res
			carry >>= p.baseLog - 1
			c += carry
			res -= carry << p.baseLog
			d[p.level-j-1].Coeffs[i] = res
		}
	}
}

// ParametersLiteral is a structure for binary TFHE parameters.
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T Tint] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	// Length of LWE secret key is LWEDimension, and the length of LWE ciphertext is LWEDimension+1.
	LWEDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and the length of GLWE ciphertext is GLWEDimension+1.
	GLWEDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	PolyDegree int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	LWEStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	GLWEStdDev float64

	// MessageModulus is the modulus of the encoded message.
	MessageModulus T
	// Delta is the scaling factor Q/P.
	Delta T

	// BootstrapParameters is the decomposition parameters for Programmable Bootstrapping.
	BootstrapParameters DecompositionParametersLiteral[T]
	// KeySwitchParameters is the decomposition parameters for KeySwitching.
	KeySwitchParameters DecompositionParametersLiteral[T]
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
func (p ParametersLiteral[T]) Compile() Parameters[T] {
	switch {
	case p.LWEDimension <= 0:
		panic("LWEDimension smaller than zero")
	case p.GLWEDimension <= 0:
		panic("GLWEDimension smaller than zero")
	case p.PolyDegree <= 0:
		panic("PolyDegree smaller than zero")
	case p.LWEStdDev <= 0:
		panic("LWEStdDev smaller than zero")
	case p.GLWEStdDev <= 0:
		panic("GLWEStdDev smaller than zero")
	case !num.IsPowerOfTwo(p.Delta):
		panic("Delta not power of two")
	case !num.IsPowerOfTwo(p.MessageModulus):
		panic("MessageModulus not power of two")
	}

	deltaLog := num.Log2(p.Delta)
	messageModulusLog := num.Log2(p.MessageModulus)

	if deltaLog+messageModulusLog > num.SizeT[T]() {
		panic("Moduli too large")
	}

	return Parameters[T]{
		lweDimension:  p.LWEDimension,
		glweDimension: p.GLWEDimension,
		polyDegree:    p.PolyDegree,

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		delta:             p.Delta,
		deltaLog:          deltaLog,
		messageModulus:    p.MessageModulus,
		messageModulusLog: messageModulusLog,

		bootstrapParameters: p.BootstrapParameters.Compile(),
		keyswitchParameters: p.KeySwitchParameters.Compile(),
	}
}

// Parameters are read-only, compiled parameters based on ParametersLiteral.
type Parameters[T Tint] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	// Length of LWE secret key is LWEDimension, and the length of LWE ciphertext is LWEDimension+1.
	lweDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and the length of GLWE ciphertext is GLWEDimension+1.
	glweDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	polyDegree int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	lweStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	glweStdDev float64

	// Delta is the scaling factor used for message encoding.
	// The lower log(Delta) bits are reserved for errors.
	delta T
	// DeltaLog equals log(Delta).
	deltaLog int
	// MessageModulus is the modulus of the encoded message.
	messageModulus T
	// MessageModulusLog equals log(MessageModulus).
	messageModulusLog int
	// carryModulus is the modulus of the carry.

	// bootstrapParameters is the decomposition parameters for Programmable Bootstrapping.
	bootstrapParameters DecompositionParameters[T]
	// keyswitchParameters is the decomposition parameters for KeySwitching.
	keyswitchParameters DecompositionParameters[T]
}

// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
// Length of LWE secret key is LWEDimension, and the length of LWE ciphertext is LWEDimension+1.
func (p Parameters[T]) LWEDimension() int {
	return p.lweDimension
}

// LargeLWEDimension is the dimension of LWE cipehrtext after Sample Extraction.
// Equal to PolyDegree * GLWEDimension.
func (p Parameters[T]) LargeLWEDimension() int {
	return p.polyDegree * p.glweDimension
}

// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
// Length of GLWE secret key is GLWEDimension, and the length of GLWE ciphertext is GLWEDimension+1.
func (p Parameters[T]) GLWEDimension() int {
	return p.glweDimension
}

// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
func (p Parameters[T]) PolyDegree() int {
	return p.polyDegree
}

// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
func (p Parameters[T]) LWEStdDev() float64 {
	return p.lweStdDev
}

// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
func (p Parameters[T]) GLWEStdDev() float64 {
	return p.glweStdDev
}

// Delta is the scaling factor used for message encoding.
// The lower log(Delta) bits are reserved for errors.
func (p Parameters[T]) Delta() T {
	return p.delta
}

// DeltaLog equals log(Delta).
func (p Parameters[T]) DeltaLog() int {
	return p.deltaLog
}

// MessageModulus is the modulus of the encoded message.
func (p Parameters[T]) MessageModulus() T {
	return p.messageModulus
}

// MessageModulusLog equals log(MessageModulus).
func (p Parameters[T]) MessageModulusLog() int {
	return p.messageModulusLog
}

// BootstrapParameters is the decomposition parameters for Programmable Bootstrapping.
func (p Parameters[T]) BootstrapParameters() DecompositionParameters[T] {
	return p.bootstrapParameters
}

// KeySwitchParameters is the decomposition parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParameters() DecompositionParameters[T] {
	return p.keyswitchParameters
}

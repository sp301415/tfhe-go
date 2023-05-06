package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
)

var (
	// ParamsMessage4Carry0 ensures 4 bit of message space and 0 bit of carry space.
	ParamsMessage4Carry0 = ParametersLiteral[uint64]{
		LWEDimension:  742,
		GLWEDimension: 1,
		PolyDegree:    2048,

		LWEStdDev:  0,
		GLWEStdDev: 0.00000000000000029403601535432533,

		Delta:          1 << (63 - 4 - 0),
		MessageModulus: 1 << 4,
		CarryModulus:   1 << 0,

		PBSParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeyswitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 3,
		},
	}.Compile()
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
	case num.TLen[T]() <= num.Log2(p.Base)+p.Level:
		panic("Base * Level larger than Q")
	}
	return DecompositionParameters[T]{
		base:    p.Base,
		baseLog: num.Log2(p.Base),
		maxBits: num.TLen[T](),
		level:   p.Level,
	}
}

type DecompositionParameters[T Tint] struct {
	base    T
	baseLog int
	maxBits int
	level   int
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

	// Delta is the scaling factor used for message encoding.
	// The lower log(Delta) bits are reserved for errors.
	Delta T
	// MessageModulus is the largest message that could be encoded.
	MessageModulus T
	// CarryModulus is the size of the carry buffer.
	CarryModulus T

	// PBSParameters is the decomposition parameters for Programmable Bootstrapping.
	PBSParameters DecompositionParametersLiteral[T]
	// KeyswitchParameters is the decomposition parameters for Keyswitching.
	KeyswitchParameters DecompositionParametersLiteral[T]
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
	case !num.IsPowerOfTwo(p.CarryModulus):
		panic("CarryModulus not power of two")
	}

	return Parameters[T]{
		lweDimension:  p.LWEDimension,
		glweDimension: p.GLWEDimension,
		polyDegree:    p.PolyDegree,

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		delta:             p.Delta,
		deltaLog:          num.Log2(p.Delta),
		messageModulus:    p.MessageModulus,
		messageModulusLog: num.Log2(p.MessageModulus),
		carryModulus:      p.CarryModulus,
		carryModulusLog:   num.Log2(p.CarryModulus),

		pbsParameters:       p.PBSParameters.Compile(),
		keyswitchParameters: p.KeyswitchParameters.Compile(),
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
	// MessageModulus is the largest message that could be encoded.
	messageModulus T
	// MessageModulusLog equals log(MessageModulus).
	messageModulusLog int
	// CarryModulus is the size of the carry buffer.
	carryModulus T
	// CarryModulusLog equals log(CarryModulus).
	carryModulusLog int

	// pbsParameters is the decomposition parameters for Programmable Bootstrapping.
	pbsParameters DecompositionParameters[T]
	// keyswitchParameters is the decomposition parameters for Keyswitching.
	keyswitchParameters DecompositionParameters[T]
}

// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
// Length of LWE secret key is LWEDimension, and the length of LWE ciphertext is LWEDimension+1.
func (p Parameters[T]) LWEDimension() int {
	return p.lweDimension
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

// MessageModulusLog equals log(MessageModulus).
func (p Parameters[T]) MessageModulusLog() int {
	return p.messageModulusLog
}

// CarryModulusLog equals log(CarryModulus).
func (p Parameters[T]) CarryModulusLog() int {
	return p.carryModulusLog
}

// MessageModulus is the largest message that could be encoded.
func (p Parameters[T]) MessageModulus() T {
	return p.messageModulus
}

// CarryModulus is the size of the carry buffer.
func (p Parameters[T]) CarryModulus() T {
	return p.carryModulus
}

// PBSParameters is the decomposition parameters for Programmable Bootstrapping.
func (p Parameters[T]) PBSParameters() DecompositionParameters[T] {
	return p.pbsParameters
}

// KeyswitchParameters is the decomposition parameters for Keyswitching.
func (p Parameters[T]) KeyswitchParameters() DecompositionParameters[T] {
	return p.keyswitchParameters
}

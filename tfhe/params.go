package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
)

var (
	// ParamsMessage1Carry0 is a default boolean parameters set with 128-bit security.
	ParamsMessage1Carry0 = ParametersLiteral[uint32]{
		LWEDimension:  777,
		GLWEDimension: 3,
		PolyDegree:    512,

		LWEStdDev:  0.000003725679281679651,
		GLWEStdDev: 0.0000000000034525330484572114,

		Delta:          1 << 24,
		MessageModulus: 1 << 1,
		CarryModulus:   1 << 0,
	}.Compile()

	// ParamsMessage4Carry0 ensures 4 bit of message space and 0 bit of carry space.
	ParamsMessage4Carry0 = ParametersLiteral[uint64]{
		LWEDimension:  742,
		GLWEDimension: 1,
		PolyDegree:    2048,

		LWEStdDev:  0.000007069849454709433,
		GLWEStdDev: 0.00000000000000029403601535432533,

		Delta:          1 << (63 - 4 - 0),
		MessageModulus: 1 << 4,
		CarryModulus:   1 << 0,
	}.Compile()
)

// Tint represents the integer in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type Tint interface {
	uint32 | uint64
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
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there are invalid parameter in the literal, it panics.
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

		delta:          p.Delta,
		messageModulus: p.MessageModulus,
		carryModulus:   p.CarryModulus,
	}
}

// Parameters are read-only, compiled parameters based on ParametersLiteral.
// For explanation of each fields, see ParametersLiteral.
type Parameters[T Tint] struct {
	lweDimension  int
	glweDimension int
	polyDegree    int

	lweStdDev  float64
	glweStdDev float64

	delta          T
	messageModulus T
	carryModulus   T
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

// MessageModulus is the largest message that could be encoded.
func (p Parameters[T]) MessageModulus() T {
	return p.messageModulus
}

// CarryModulus is the size of the carry buffer.
func (p Parameters[T]) CarryModulus() T {
	return p.carryModulus
}

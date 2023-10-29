package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
)

const (
	// MaxPolyDegree is the maximum degree of polynomials in GLWE entities.
	// We use FFT for GLWE encryption, which limits the maximum degree due to precision loss.
	MaxPolyDegree = 1 << 20
)

// Tint represents the integer in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type Tint interface {
	uint32 | uint64
}

// DecompositionParametersLiteral is a Parameter Literal for gadget decomposition,
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
		base:            p.Base,
		baseHalf:        p.Base / 2,
		baseMask:        p.Base - 1,
		baseLog:         baseLog,
		baseLogMinusOne: baseLog - 1,
		level:           p.Level,
		scaledBasesLog:  scaledBasesLog,
	}
}

// DecompositionParameters is a read-only, compiled parameters based on DecompositionParametersLiteral.
type DecompositionParameters[T Tint] struct {
	// Base is a base of gadget. It must be power of two.
	base T
	// BaseHalf equals Base / 2.
	baseHalf T
	// BaseMask equals Base - 1.
	// This is used for modulo operation, where c % Base equals c & BaseMask.
	baseMask T
	// BaseLog equals log(Base).
	baseLog int
	// BaseLogMinusOne equals BaseLog - 1.
	baseLogMinusOne int
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

// ParametersLiteral is a structure for TFHE parameters.
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T Tint] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	// Length of LWE secret key is LWEDimension, and length of LWE ciphertext is LWEDimension+1.
	LWEDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and length of GLWE ciphertext is GLWEDimension+1.
	GLWEDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	PolyDegree int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	LWEStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	GLWEStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	BlockSize int

	// MessageModulus is the modulus of the encoded message.
	MessageModulus T

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
	case p.PolyDegree > MaxPolyDegree:
		panic("PolyDegree larger than MaxPolyDegree")
	case p.LWEStdDev <= 0:
		panic("LWEStdDev smaller than zero")
	case p.GLWEStdDev <= 0:
		panic("GLWEStdDev smaller than zero")
	case p.LWEDimension%p.BlockSize != 0:
		panic("LWEDimension not multiple of BlockSize")
	case !num.IsPowerOfTwo(p.PolyDegree):
		panic("PolyDegree not power of two")
	case !num.IsPowerOfTwo(p.MessageModulus):
		panic("MessageModulus not power of two")
	}

	messageModulusLog := num.Log2(p.MessageModulus)
	deltaLog := num.SizeT[T]() - 1 - messageModulusLog

	return Parameters[T]{
		lweDimension:  p.LWEDimension,
		glweDimension: p.GLWEDimension,
		polyDegree:    p.PolyDegree,
		polyDegreeLog: num.Log2(p.PolyDegree),

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		blockSize: p.BlockSize,

		messageModulus:    p.MessageModulus,
		messageModulusLog: messageModulusLog,
		delta:             1 << deltaLog,
		deltaLog:          deltaLog,

		sizeT: num.SizeT[T](),
		maxT:  T(num.MaxT[T]()),

		bootstrapParameters: p.BootstrapParameters.Compile(),
		keyswitchParameters: p.KeySwitchParameters.Compile(),
	}
}

// Parameters are read-only, compiled parameters based on ParametersLiteral.
type Parameters[T Tint] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	// Length of LWE secret key is LWEDimension, and length of LWE ciphertext is LWEDimension+1.
	lweDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and length of GLWE ciphertext is GLWEDimension+1.
	glweDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	polyDegree int
	// PolyDegreeLog equals log(PolyDegree).
	polyDegreeLog int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	lweStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	glweStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	blockSize int

	// MessageModulus is the modulus of the encoded message.
	messageModulus T
	// MessageModulusLog equals log(MessageModulus).
	messageModulusLog int
	// Delta is the scaling factor used for message encoding.
	// The lower log(Delta) bits are reserved for errors.
	delta T
	// DeltaLog equals log(Delta).
	deltaLog int

	// maxT is the maximum value of T.
	maxT T
	// sizeT is the bit length of T.
	sizeT int

	// bootstrapParameters is the decomposition parameters for Programmable Bootstrapping.
	bootstrapParameters DecompositionParameters[T]
	// keyswitchParameters is the decomposition parameters for KeySwitching.
	keyswitchParameters DecompositionParameters[T]
}

// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
// Length of LWE secret key is LWEDimension, and length of LWE ciphertext is LWEDimension+1.
func (p Parameters[T]) LWEDimension() int {
	return p.lweDimension
}

// LargeLWEDimension is the dimension of LWE cipehrtext after Sample Extraction.
// Equal to PolyDegree * GLWEDimension.
func (p Parameters[T]) LargeLWEDimension() int {
	return p.polyDegree * p.glweDimension
}

// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
// Length of GLWE secret key is GLWEDimension, and length of GLWE ciphertext is GLWEDimension+1.
func (p Parameters[T]) GLWEDimension() int {
	return p.glweDimension
}

// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
func (p Parameters[T]) PolyDegree() int {
	return p.polyDegree
}

// PolyDegreeLog equals log(PolyDegree).
func (p Parameters[T]) PolyDegreeLog() int {
	return p.polyDegreeLog
}

// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
func (p Parameters[T]) LWEStdDev() float64 {
	return p.lweStdDev
}

// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
func (p Parameters[T]) GLWEStdDev() float64 {
	return p.glweStdDev
}

// BlockSize is the size of block to be used for LWE key sampling.
func (p Parameters[T]) BlockSize() int {
	return p.blockSize
}

// BlockCount is a number of blocks in LWE key. Equal to LWEDimension / BlockSize.
func (p Parameters[T]) BlockCount() int {
	return p.lweDimension / p.blockSize
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

// MaxT is the maximum value of T.
func (p Parameters[T]) MaxT() T {
	return p.maxT
}

// SizeT is the bit length of T.
func (p Parameters[T]) SizeT() int {
	return p.sizeT
}

// BootstrapParameters is the decomposition parameters for Programmable Bootstrapping.
func (p Parameters[T]) BootstrapParameters() DecompositionParameters[T] {
	return p.bootstrapParameters
}

// KeySwitchParameters is the decomposition parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParameters() DecompositionParameters[T] {
	return p.keyswitchParameters
}

package tfhe

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/sp301415/tfhe-go/math/num"
)

const (
	// MinPolyDegree is the minimum degree of polynomials allowed in parameters.
	// Currently polynomial decomposition is implemented using AVX2,
	// which requires degree at least 256/32 = 8.
	MinPolyDegree = 1 << 3

	// MaxPolyDegree is the maximum degree of polynomials allowed in parameters.
	// We use FFT for GLWE encryption, which limits the maximum degree due to precision loss.
	MaxPolyDegree = 1 << 20
)

// Tint represents the integer in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type Tint interface {
	uint32 | uint64
}

// GadgetParametersLiteral is a structure for Gadget Decomposition,
// which is used in Lev, GSW, GLev and GGSW encryptions.
type GadgetParametersLiteral[T Tint] struct {
	// Base is a base of gadget. It must be power of two.
	Base T
	// Level is a length of gadget.
	Level int
}

// Compile transforms GadgetParametersLiteral to read-only GadgetParameters.
// If there is any invalid parameter in the literal, it panics.
func (p GadgetParametersLiteral[T]) Compile() GadgetParameters[T] {
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

	return GadgetParameters[T]{
		base:            p.Base,
		baseHalf:        p.Base / 2,
		baseMask:        p.Base - 1,
		baseLog:         baseLog,
		baseLogMinusOne: baseLog - 1,
		level:           p.Level,
		scaledBasesLog:  scaledBasesLog,
	}
}

// GadgetParameters is a read-only, compiled parameters based on GadgetParametersLiteral.
type GadgetParameters[T Tint] struct {
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
func (p GadgetParameters[T]) Base() T {
	return p.base
}

// BaseLog equals log(Base).
func (p GadgetParameters[T]) BaseLog() int {
	return p.baseLog
}

// Level is a length of gadget.
func (p GadgetParameters[T]) Level() int {
	return p.level
}

// ScaledBase returns Q / Base^(i+1) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use FirstScaledBase() and LastScaledBase().
func (p GadgetParameters[T]) ScaledBase(i int) T {
	return T(1 << p.scaledBasesLog[i])
}

// FirstScaledBase returns Q / Base.
func (p GadgetParameters[T]) FirstScaledBase() T {
	return p.ScaledBase(0)
}

// LastScaledBase returns Q / Base^Level.
func (p GadgetParameters[T]) LastScaledBase() T {
	return p.ScaledBase(p.level - 1)
}

// ScaledBaseLog returns log(Q / Base^(i+1)) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use FirstScaledBaseLog() and LastScaledBaseLog().
func (p GadgetParameters[T]) ScaledBaseLog(i int) int {
	return p.scaledBasesLog[i]
}

// FirstScaledBaseLog returns log(Q / Base).
func (p GadgetParameters[T]) FirstScaledBaseLog() int {
	return p.ScaledBaseLog(0)
}

// LastScaledBaseLog returns log(Q / Base^Level).
func (p GadgetParameters[T]) LastScaledBaseLog() int {
	return p.ScaledBaseLog(p.level - 1)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
// This never returns an error.
func (p GadgetParameters[T]) MarshalBinary() (data []byte, err error) {
	base := uint64(p.base)
	level := uint64(p.level)

	data = make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], base)
	binary.BigEndian.PutUint64(data[8:16], level)

	return
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// If the data is invalid, it returns an error.
// If the parameters are invalid, it panics.
func (p *GadgetParameters[T]) UnmarshalBinary(data []byte) error {
	if len(data) != 16 {
		return errors.New("data length mismatch")
	}

	base := binary.BigEndian.Uint64(data[:8])
	level := binary.BigEndian.Uint64(data[8:16])

	*p = GadgetParametersLiteral[T]{
		Base:  T(base),
		Level: int(level),
	}.Compile()

	return nil
}

// ParametersLiteral is a structure for TFHE parameters.
//
// # Warning
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

	// BootstrapParameters is the gadget parameters for Programmable Bootstrapping.
	BootstrapParameters GadgetParametersLiteral[T]
	// KeySwitchParameters is the gadget parameters for KeySwitching.
	KeySwitchParameters GadgetParametersLiteral[T]
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
//
// # Warning
//
// This method performs only basic sanity checks.
// Just because a parameter compiles does not necessarily mean it is safe or correct.
// Unless you are a cryptographic expert, DO NOT set parameters by yourself;
// always use the default parameters provided.
func (p ParametersLiteral[T]) Compile() Parameters[T] {
	switch {
	case p.LWEDimension <= 0:
		panic("LWEDimension smaller than zero")
	case p.GLWEDimension <= 0:
		panic("GLWEDimension smaller than zero")
	case p.PolyDegree <= MinPolyDegree:
		panic("PolyDegree smaller than MinPolyDegree")
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

	// bootstrapParameters is the gadget parameters for Programmable Bootstrapping.
	bootstrapParameters GadgetParameters[T]
	// keyswitchParameters is the gadget parameters for KeySwitching.
	keyswitchParameters GadgetParameters[T]
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

// BootstrapParameters is the gadget parameters for Programmable Bootstrapping.
func (p Parameters[T]) BootstrapParameters() GadgetParameters[T] {
	return p.bootstrapParameters
}

// KeySwitchParameters is the gadget parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParameters() GadgetParameters[T] {
	return p.keyswitchParameters
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
// This never returns an error.
func (p Parameters[T]) MarshalBinary() (data []byte, err error) {
	lweDimension := uint64(p.lweDimension)
	glweDimension := uint64(p.glweDimension)
	polyDegree := uint64(p.polyDegree)
	lweStdDev := math.Float64bits(p.lweStdDev)
	glweStdDev := math.Float64bits(p.glweStdDev)
	blockSize := uint64(p.blockSize)
	messageModulus := uint64(p.messageModulus)

	data = make([]byte, 3*8+2*8+8+8+16+16)

	binary.BigEndian.PutUint64(data[0:8], lweDimension)
	binary.BigEndian.PutUint64(data[8:16], glweDimension)
	binary.BigEndian.PutUint64(data[16:24], polyDegree)
	binary.BigEndian.PutUint64(data[24:32], lweStdDev)
	binary.BigEndian.PutUint64(data[32:40], glweStdDev)
	binary.BigEndian.PutUint64(data[40:48], blockSize)
	binary.BigEndian.PutUint64(data[48:56], messageModulus)

	bootstrapParameters, _ := p.bootstrapParameters.MarshalBinary()
	keyswitchParameters, _ := p.keyswitchParameters.MarshalBinary()

	data = append(data, bootstrapParameters...)
	data = append(data, keyswitchParameters...)

	return
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// If the data is invalid, it returns an error.
// If the parameters are invalid, it panics.
func (p *Parameters[T]) UnmarshalBinary(data []byte) error {
	if len(data) != 3*8+2*8+8+8+16+16 {
		return errors.New("data length mismatch")
	}

	lweDimension := binary.BigEndian.Uint64(data[0:8])
	glweDimension := binary.BigEndian.Uint64(data[8:16])
	polyDegree := binary.BigEndian.Uint64(data[16:24])
	lweStdDev := math.Float64frombits(binary.BigEndian.Uint64(data[24:32]))
	glweStdDev := math.Float64frombits(binary.BigEndian.Uint64(data[32:40]))
	blockSize := binary.BigEndian.Uint64(data[40:48])
	messageModulus := binary.BigEndian.Uint64(data[48:56])

	bootstrapParameters := GadgetParametersLiteral[T]{
		Base:  T(binary.BigEndian.Uint64(data[56:64])),
		Level: int(binary.BigEndian.Uint64(data[64:72])),
	}
	keyswitchParameters := GadgetParametersLiteral[T]{
		Base:  T(binary.BigEndian.Uint64(data[72:80])),
		Level: int(binary.BigEndian.Uint64(data[80:88])),
	}

	*p = ParametersLiteral[T]{
		LWEDimension:        int(lweDimension),
		GLWEDimension:       int(glweDimension),
		PolyDegree:          int(polyDegree),
		LWEStdDev:           lweStdDev,
		GLWEStdDev:          glweStdDev,
		BlockSize:           int(blockSize),
		MessageModulus:      T(messageModulus),
		BootstrapParameters: bootstrapParameters,
		KeySwitchParameters: keyswitchParameters,
	}.Compile()

	return nil
}

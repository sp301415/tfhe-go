package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
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

// TorusInt represents the integers living in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type TorusInt interface {
	uint32 | uint64
}

// GadgetParametersLiteral is a structure for Gadget Decomposition,
// which is used in Lev, GSW, GLev and GGSW encryptions.
type GadgetParametersLiteral[T TorusInt] struct {
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
type GadgetParameters[T TorusInt] struct {
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

// ByteSize returns the byte size of the gadget parameters.
func (p GadgetParameters[T]) ByteSize() int {
	return 16
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
func (p GadgetParameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(p.base))
	binary.BigEndian.PutUint64(buf[8:16], uint64(p.level))

	nn, err := w.Write(buf[:])
	n += int64(nn)
	if err != nil {
		return
	}

	if n < int64(p.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (p *GadgetParameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var buf [16]byte
	nn, err := io.ReadFull(r, buf[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := binary.BigEndian.Uint64(buf[0:8])
	level := binary.BigEndian.Uint64(buf[8:16])

	*p = GadgetParametersLiteral[T]{
		Base:  T(base),
		Level: int(level),
	}.Compile()

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (p GadgetParameters[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, p.ByteSize()))
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (p *GadgetParameters[T]) UnmarshalBinary(data []byte) error {
	_, err := p.ReadFrom(bytes.NewReader(data))
	return err
}

// BootstrapOrder is an enum type for the order of Programmable Bootstrapping.
type BootstrapOrder int

const (
	// OrderKeySwitchBlindRotate sets the order of Programmable Bootstrapping as
	//
	//	KeySwitch -> BlindRotate -> SampleExtract
	//
	// This means that LWE keys and ciphertexts will have size
	// according to LWELargeDimension.
	OrderKeySwitchBlindRotate BootstrapOrder = iota

	// OrderBlindRotateKeySwitch sets the order of Programmable Bootstrapping as
	//
	//	BlindRotate -> SampleExtract -> KeySwitch
	//
	// This means that LWE keys and ciphertexts will have size
	// according to LWEDimension.
	OrderBlindRotateKeySwitch
)

// ParametersLiteral is a structure for TFHE parameters.
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T TorusInt] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	LWEDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and length of GLWE ciphertext is GLWEDimension+1.
	GLWEDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	PolyDegree int
	// PolyLargeDegree is the degree of polynomial used in Blind Roation.
	//
	// This is used in Extended Bootstrapping, as explained in https://eprint.iacr.org/2023/402.
	// To use the original TFHE bootstrapping, set this to PolyDegree.
	PolyLargeDegree int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	LWEStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	GLWEStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	//
	// This is used in Block Binary Key distribution, as explained in https://eprint.iacr.org/2023/958.
	// To use the original TFHE bootstrapping, set this to 1.
	BlockSize int

	// MessageModulus is the modulus of the encoded message.
	MessageModulus T

	// BootstrapParameters is the gadget parameters for Programmable Bootstrapping.
	BootstrapParameters GadgetParametersLiteral[T]
	// KeySwitchParameters is the gadget parameters for KeySwitching.
	KeySwitchParameters GadgetParametersLiteral[T]

	// BootstrapOrder is the order of Programmable Bootstrapping.
	// If this is set to OrderKeySwitchBlindRotate, then the order is:
	//
	//	KeySwitch -> BlindRotate -> SampleExtract
	//
	// and LWE keys and ciphertexts will have size according to LWELargeDimension.
	//
	// Otherwise, if this is set to OrderBlindRotateKeySwitch, the order is:
	//
	//	BlindRotate -> SampleExtract -> KeySwitch
	//
	// and LWE keys and ciphertexts will have size according to LWEDimension.
	//
	// Essentially, there is a time-memory tradeoff:
	// performing keyswitching first means that it will consume more memory,
	// but it allows to use smaller parameters which will result in faster computation.
	BootstrapOrder BootstrapOrder
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
	case p.LWEDimension > p.GLWEDimension*p.PolyDegree:
		panic("LWEDimension larger than GLWEDimension * PolyDegree")
	case p.GLWEDimension <= 0:
		panic("GLWEDimension smaller than zero")
	case p.PolyDegree < MinPolyDegree:
		panic("PolyDegree smaller than MinPolyDegree")
	case p.PolyDegree > MaxPolyDegree:
		panic("PolyDegree larger than MaxPolyDegree")
	case p.PolyLargeDegree < MinPolyDegree:
		panic("PolyLargeDegree smaller than MinPolyDegree")
	case p.PolyLargeDegree > MaxPolyDegree:
		panic("PolyLargeDegree larger than MaxPolyDegree")
	case p.PolyLargeDegree < p.PolyDegree:
		panic("PolyLargeDegree smaller than PolyDegree")
	case p.LWEStdDev <= 0:
		panic("LWEStdDev smaller than zero")
	case p.GLWEStdDev <= 0:
		panic("GLWEStdDev smaller than zero")
	case p.BlockSize <= 0:
		panic("BlockSize smaller than zero")
	case p.LWEDimension%p.BlockSize != 0:
		panic("LWEDimension not multiple of BlockSize")
	case !num.IsPowerOfTwo(p.PolyDegree):
		panic("PolyDegree not power of two")
	case !num.IsPowerOfTwo(p.PolyLargeDegree):
		panic("PolyLargeDegree not power of two")
	case !num.IsPowerOfTwo(p.MessageModulus):
		panic("MessageModulus not power of two")
	case !(p.BootstrapOrder == OrderKeySwitchBlindRotate || p.BootstrapOrder == OrderBlindRotateKeySwitch):
		panic("BootstrapOrder not valid")
	}

	messageModulusLog := num.Log2(p.MessageModulus)
	deltaLog := num.SizeT[T]() - 1 - messageModulusLog

	return Parameters[T]{
		lweDimension:        p.LWEDimension,
		lweLargeDimension:   p.GLWEDimension * p.PolyDegree,
		glweDimension:       p.GLWEDimension,
		polyDegree:          p.PolyDegree,
		polyDegreeLog:       num.Log2(p.PolyDegree),
		polyLargeDegree:     p.PolyLargeDegree,
		polyLargeDegreeLog:  num.Log2(p.PolyLargeDegree),
		polyExtendFactor:    p.PolyLargeDegree / p.PolyDegree,
		polyExtendFactorLog: num.Log2(p.PolyLargeDegree / p.PolyDegree),

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		blockSize:  p.BlockSize,
		blockCount: p.LWEDimension / p.BlockSize,

		messageModulus:    p.MessageModulus,
		messageModulusLog: messageModulusLog,
		delta:             1 << deltaLog,
		deltaLog:          deltaLog,

		sizeT: num.SizeT[T](),
		maxT:  T(num.MaxT[T]()),

		bootstrapParameters: p.BootstrapParameters.Compile(),
		keyswitchParameters: p.KeySwitchParameters.Compile(),

		bootstrapOrder: p.BootstrapOrder,
	}
}

// Parameters are read-only, compiled parameters based on ParametersLiteral.
type Parameters[T TorusInt] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	lweDimension int
	// LWELargeDimension is the dimension of "large" lattice used.
	// Equals to the "full" GLWE lattice; which is GLWEDimension * PolyDegree.
	lweLargeDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and length of GLWE ciphertext is GLWEDimension+1.
	glweDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	polyDegree int
	// PolyDegreeLog equals log(PolyDegree).
	polyDegreeLog int
	// PolyLargeDegree is the degree of polynomial used in Blind Roation.
	polyLargeDegree int
	// PolyLargeDegreeLog equals log(PolyLargeDegree).
	polyLargeDegreeLog int
	// polyExtendFactor equals PolyLargeDegree / PolyDegree.
	polyExtendFactor int
	// polyExtendFactorLog equals log(PolyLargeDegree / PolyDegree).
	polyExtendFactorLog int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	lweStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	glweStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	blockSize int
	// BlockCount is a number of blocks in LWEkey. Equal to LWEDimension / BlockSize.
	blockCount int

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

	// bootstrapOrder is the order of Programmable Bootstrapping.
	bootstrapOrder BootstrapOrder
}

// DefaultLWEDimension returns the default dimension for LWE entities.
// Returns LWEDimension if BootstrapOrder is OrderBlindRotateKeySwitch,
// and LWELargeDimension otherwise.
func (p Parameters[T]) DefaultLWEDimension() int {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweDimension
	}
	return p.lweLargeDimension
}

// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
func (p Parameters[T]) LWEDimension() int {
	return p.lweDimension
}

// LWELargeDimension is the dimension of "large" lattice used.
// Equals to the "full" GLWE lattice; which is GLWEDimension * PolyDegree.
func (p Parameters[T]) LWELargeDimension() int {
	return p.lweLargeDimension
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

// PolyLargeDegree is the degree of polynomial used in Blind Roation.
func (p Parameters[T]) PolyLargeDegree() int {
	return p.polyLargeDegree
}

// PolyLargeDegreeLog equals log(PolyLargeDegree).
func (p Parameters[T]) PolyLargeDegreeLog() int {
	return p.polyLargeDegreeLog
}

// PolyExtendFactor returns PolyLargeDegree / PolyDegree.
func (p Parameters[T]) PolyExtendFactor() int {
	return p.polyExtendFactor
}

// PolyExtendFactorLog returns log(PolyLargeDegree / PolyDegree).
func (p Parameters[T]) PolyExtendFactorLog() int {
	return p.polyExtendFactorLog
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

// BlockCount is a number of blocks in LWEkey. Equal to LWEDimension / BlockSize.
func (p Parameters[T]) BlockCount() int {
	return p.blockCount
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

// BootstrapOrder is the order of Programmable Bootstrapping.
func (p Parameters[T]) BootstrapOrder() BootstrapOrder {
	return p.bootstrapOrder
}

// ByteSize returns the byte size of the parameters.
func (p Parameters[T]) ByteSize() int {
	return 7*8 + 2*16 + 1
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[ 8] LWEDimension
//	[ 8] GLWEDimension
//	[ 8] PolyDegree
//	[ 8] PolyLargeDegree
//	[ 8] LWEStdDev
//	[ 8] GLWEStdDev
//	[ 8] BlockSize
//	[ 8] MessageModulus
//	[16] BootstrapParameters
//	[16] KeySwitchParameters
//	[ 1] BootstrapOrder
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var buf [8*8 + 2*16 + 1]byte

	binary.BigEndian.PutUint64(buf[0:8], uint64(p.lweDimension))
	binary.BigEndian.PutUint64(buf[8:16], uint64(p.glweDimension))
	binary.BigEndian.PutUint64(buf[16:24], uint64(p.polyDegree))
	binary.BigEndian.PutUint64(buf[24:32], uint64(p.polyLargeDegree))
	binary.BigEndian.PutUint64(buf[32:40], math.Float64bits(p.lweStdDev))
	binary.BigEndian.PutUint64(buf[40:48], math.Float64bits(p.glweStdDev))
	binary.BigEndian.PutUint64(buf[48:56], uint64(p.blockSize))
	binary.BigEndian.PutUint64(buf[56:64], uint64(p.messageModulus))
	binary.BigEndian.PutUint64(buf[64:72], uint64(p.bootstrapParameters.Base()))
	binary.BigEndian.PutUint64(buf[72:80], uint64(p.bootstrapParameters.Level()))
	binary.BigEndian.PutUint64(buf[80:88], uint64(p.keyswitchParameters.Base()))
	binary.BigEndian.PutUint64(buf[88:96], uint64(p.keyswitchParameters.Level()))
	buf[96] = byte(p.bootstrapOrder)

	nn, err := w.Write(buf[:])
	n += int64(nn)
	if err != nil {
		return
	}

	if n < int64(p.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (p *Parameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var buf [8*8 + 2*16 + 1]byte
	nn, err := io.ReadFull(r, buf[:])
	n += int64(nn)
	if err != nil {
		return
	}

	lweDimension := binary.BigEndian.Uint64(buf[0:8])
	glweDimension := binary.BigEndian.Uint64(buf[8:16])
	polyDegree := binary.BigEndian.Uint64(buf[16:24])
	polyLargeDegree := binary.BigEndian.Uint64(buf[24:32])
	lweStdDev := math.Float64frombits(binary.BigEndian.Uint64(buf[32:40]))
	glweStdDev := math.Float64frombits(binary.BigEndian.Uint64(buf[40:48]))
	blockSize := binary.BigEndian.Uint64(buf[48:56])
	messageModulus := binary.BigEndian.Uint64(buf[56:64])

	bootstrapParameters := GadgetParametersLiteral[T]{
		Base:  T(binary.BigEndian.Uint64(buf[64:72])),
		Level: int(binary.BigEndian.Uint64(buf[72:80])),
	}
	keyswitchParameters := GadgetParametersLiteral[T]{
		Base:  T(binary.BigEndian.Uint64(buf[80:88])),
		Level: int(binary.BigEndian.Uint64(buf[88:96])),
	}

	bootstrapOrder := BootstrapOrder(buf[96])

	*p = ParametersLiteral[T]{
		LWEDimension:        int(lweDimension),
		GLWEDimension:       int(glweDimension),
		PolyDegree:          int(polyDegree),
		PolyLargeDegree:     int(polyLargeDegree),
		LWEStdDev:           lweStdDev,
		GLWEStdDev:          glweStdDev,
		BlockSize:           int(blockSize),
		MessageModulus:      T(messageModulus),
		BootstrapParameters: bootstrapParameters,
		KeySwitchParameters: keyswitchParameters,
		BootstrapOrder:      bootstrapOrder,
	}.Compile()

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (p Parameters[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, p.ByteSize()))
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (p *Parameters[T]) UnmarshalBinary(data []byte) error {
	_, err := p.ReadFrom(bytes.NewReader(data))
	return err
}

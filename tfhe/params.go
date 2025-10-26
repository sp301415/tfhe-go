package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/math/num"
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

// WithBase sets the base and returns the new GadgetParametersLiteral.
func (p GadgetParametersLiteral[T]) WithBase(base T) GadgetParametersLiteral[T] {
	p.Base = base
	return p
}

// WithLevel sets the level and returns the new GadgetParametersLiteral.
func (p GadgetParametersLiteral[T]) WithLevel(level int) GadgetParametersLiteral[T] {
	p.Level = level
	return p
}

// Compile transforms GadgetParametersLiteral to read-only GadgetParameters.
// If there is any invalid parameter in the literal, it panics.
func (p GadgetParametersLiteral[T]) Compile() GadgetParameters[T] {
	switch {
	case p.Base < 2:
		panic("Base smaller than two")
	case !num.IsPowerOfTwo(p.Base):
		panic("Base not power of two")
	case p.Level <= 0:
		panic("Level smaller than zero")
	case num.SizeT[T]() < num.Log2(p.Base)*p.Level:
		panic("Base * Level larger than Q")
	}

	return GadgetParameters[T]{
		base:    p.Base,
		logBase: num.Log2(p.Base),
		level:   p.Level,
		sizeT:   num.SizeT[T](),
	}
}

// GadgetParameters is a read-only, compiled parameters based on GadgetParametersLiteral.
type GadgetParameters[T TorusInt] struct {
	// Base is a base of gadget. It must be power of two.
	base T
	// LogBase equals log(Base).
	logBase int
	// Level is a length of gadget.
	level int
	// sizeT is the size of T in bits.
	sizeT int
}

// Base is a base of gadget. It must be power of two.
func (p GadgetParameters[T]) Base() T {
	return p.base
}

// LogBase equals log(Base).
func (p GadgetParameters[T]) LogBase() int {
	return p.logBase
}

// Level is a length of gadget.
func (p GadgetParameters[T]) Level() int {
	return p.level
}

// BaseQ returns Q / Base^(i+1) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use [GadgetParameters.FirstBaseQ] and [GadgetParameters.LastBaseQ].
func (p GadgetParameters[T]) BaseQ(i int) T {
	return T(1 << (p.sizeT - (i+1)*p.logBase))
}

// FirstBaseQ returns Q / Base.
func (p GadgetParameters[T]) FirstBaseQ() T {
	return T(1 << (p.sizeT - p.logBase))
}

// LastBaseQ returns Q / Base^Level.
func (p GadgetParameters[T]) LastBaseQ() T {
	return T(1 << (p.sizeT - p.level*p.logBase))
}

// LogBaseQ returns log(Q / Base^(i+1)) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use [GadgetParameters.LogFirstBaseQ] and [GadgetParameters.LogLastBaseQ].
func (p GadgetParameters[T]) LogBaseQ(i int) int {
	return p.sizeT - (i+1)*p.logBase
}

// LogFirstBaseQ returns log(Q / Base).
func (p GadgetParameters[T]) LogFirstBaseQ() int {
	return p.sizeT - p.logBase
}

// LogLastBaseQ returns log(Q / Base^Level).
func (p GadgetParameters[T]) LogLastBaseQ() int {
	return p.sizeT - p.level*p.logBase
}

// Literal returns a GadgetParametersLiteral from this GadgetParameters.
func (p GadgetParameters[T]) Literal() GadgetParametersLiteral[T] {
	return GadgetParametersLiteral[T]{
		Base:  p.base,
		Level: p.level,
	}
}

// ByteSize returns the byte size of the gadget parameters.
func (p GadgetParameters[T]) ByteSize() int {
	return 16
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
func (p GadgetParameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := p.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))

	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := p.level
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if n < int64(p.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (p *GadgetParameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	base := T(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	level := int(binary.BigEndian.Uint64(buf[:]))

	*p = GadgetParametersLiteral[T]{
		Base:  base,
		Level: level,
	}.Compile()

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (p GadgetParameters[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, p.ByteSize()))
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (p *GadgetParameters[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := p.ReadFrom(buf)
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
	// according to GLWEDimension.
	// Public key encryption is supported only with this order.
	OrderKeySwitchBlindRotate BootstrapOrder = iota

	// OrderBlindRotateKeySwitch sets the order of Programmable Bootstrapping as
	//
	//	BlindRotate -> SampleExtract -> KeySwitch
	//
	// This means that LWE keys and ciphertexts will have size
	// according to LWEDimension.
	// Public key encryption is not supported with this order.
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
	// GLWERank is the rank of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWERank, and length of GLWE ciphertext is GLWERank+1.
	GLWERank int
	// PolyRank is the rank of polynomials in GLWE entities. Usually this is denoted by N.
	PolyRank int
	// LUTSize is the size of the Lookup Table used in Blind Rotation.
	//
	// In case of Extended Bootstrapping, this may differ from PolyRank as explained in https://eprint.iacr.org/2023/402.
	// Therefore, it must be a multiple of PolyRank.
	// To use the original TFHE bootstrapping, set this to PolyRank.
	//
	// If zero, then it is set to PolyRank.
	LUTSize int

	// LWEStdDev is the normalized standard deviation used for gaussian error sampling in LWE encryption.
	LWEStdDev float64
	// GLWEStdDev is the normalized standard deviation used for gaussian error sampling in GLWE encryption.
	GLWEStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	//
	// This is used in Block Binary Key distribution, as explained in https://eprint.iacr.org/2023/958.
	// To use the original TFHE bootstrapping, set this to 1.
	//
	// If zero, then it is set to 1.
	BlockSize int

	// MessageModulus is the modulus of the encoded message.
	MessageModulus T

	// BlindRotateParams is the gadget parameters for Blind Rotation.
	BlindRotateParams GadgetParametersLiteral[T]
	// KeySwitchParams is the gadget parameters for KeySwitching.
	KeySwitchParams GadgetParametersLiteral[T]

	// BootstrapOrder is the order of Programmable Bootstrapping.
	// If this is set to OrderKeySwitchBlindRotate, then the order is:
	//
	//	KeySwitch -> BlindRotate -> SampleExtract
	//
	// and LWE keys and ciphertexts will have size according to GLWEDimension.
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
	//
	// Moreover, public key encryption is supported only with OrderKeySwitchBlindRotate.
	//
	// If zero, then it is set to OrderKeySwitchBlindRotate.
	BootstrapOrder BootstrapOrder
}

// WithLWEDimension sets the LWEDimension and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLWEDimension(lweDimension int) ParametersLiteral[T] {
	p.LWEDimension = lweDimension
	return p
}

// WithGLWERank sets the GLWERank and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithGLWERank(glweRank int) ParametersLiteral[T] {
	p.GLWERank = glweRank
	return p
}

// WithPolyRank sets the PolyRank and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPolyRank(polyRank int) ParametersLiteral[T] {
	p.PolyRank = polyRank
	return p
}

// WithLUTSize sets the LUTSize and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLUTSize(lutSize int) ParametersLiteral[T] {
	p.LUTSize = lutSize
	return p
}

// WithLWEStdDev sets the LWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLWEStdDev(lweStdDev float64) ParametersLiteral[T] {
	p.LWEStdDev = lweStdDev
	return p
}

// WithGLWEStdDev sets the GLWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithGLWEStdDev(glweStdDev float64) ParametersLiteral[T] {
	p.GLWEStdDev = glweStdDev
	return p
}

// WithBlockSize sets the BlockSize and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlockSize(blockSize int) ParametersLiteral[T] {
	p.BlockSize = blockSize
	return p
}

// WithMessageModulus sets the MessageModulus and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithMessageModulus(messageModulus T) ParametersLiteral[T] {
	p.MessageModulus = messageModulus
	return p
}

// WithBlindRotateParams sets the BlindRotateParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlindRotateParams(blindRotateParams GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.BlindRotateParams = blindRotateParams
	return p
}

// WithKeySwitchParams sets the KeySwitchParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithKeySwitchParams(keySwitchParams GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.KeySwitchParams = keySwitchParams
	return p
}

// WithBootstrapOrder sets the BootstrapOrder and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBootstrapOrder(bootstrapOrder BootstrapOrder) ParametersLiteral[T] {
	p.BootstrapOrder = bootstrapOrder
	return p
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
	if p.LUTSize == 0 {
		p.LUTSize = p.PolyRank
	}
	if p.BlockSize == 0 {
		p.BlockSize = 1
	}

	switch {
	case p.LWEDimension <= 0:
		panic("LWEDimension smaller than zero")
	case p.LWEDimension > p.GLWERank*p.PolyRank:
		panic("LWEDimension larger than GLWEDimension")
	case p.GLWERank <= 0:
		panic("GLWERank smaller than zero")
	case p.LUTSize < p.PolyRank:
		panic("LUTSize smaller than PolyRank")
	case p.LWEStdDev <= 0:
		panic("LWEStdDev smaller than zero")
	case p.GLWEStdDev <= 0:
		panic("GLWEStdDev smaller than zero")
	case p.BlockSize <= 0:
		panic("BlockSize smaller than zero")
	case p.LWEDimension%p.BlockSize != 0:
		panic("LWEDimension not multiple of BlockSize")
	case p.LUTSize%p.PolyRank != 0:
		panic("LUTSize not multiple of PolyRank")
	case !num.IsPowerOfTwo(p.PolyRank):
		panic("PolyRank not power of two")
	case !(p.BootstrapOrder == OrderKeySwitchBlindRotate || p.BootstrapOrder == OrderBlindRotateKeySwitch):
		panic("BootstrapOrder not valid")
	}

	return Parameters[T]{
		lweDimension:    p.LWEDimension,
		glweDimension:   p.GLWERank * p.PolyRank,
		glweRank:        p.GLWERank,
		polyRank:        p.PolyRank,
		logPolyRank:     num.Log2(p.PolyRank),
		lutSize:         p.LUTSize,
		lutExtendFactor: p.LUTSize / p.PolyRank,

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		blockSize:  p.BlockSize,
		blockCount: p.LWEDimension / p.BlockSize,

		messageModulus: p.MessageModulus,
		scale:          num.DivRound(1<<(num.SizeT[T]()-1), p.MessageModulus),

		logQ:   num.SizeT[T](),
		floatQ: math.Exp2(float64(num.SizeT[T]())),

		blindRotateParams: p.BlindRotateParams.Compile(),
		keySwitchParams:   p.KeySwitchParams.Compile(),

		bootstrapOrder: p.BootstrapOrder,
	}
}

// Parameters are read-only, compiled parameters based on ParametersLiteral.
type Parameters[T TorusInt] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	lweDimension int
	// GLWEDimension is the dimension of GLWE lattice used, which is GLWERank * PolyRank.
	glweDimension int
	// GLWERank is the rank of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWERank, and length of GLWE ciphertext is GLWERank+1.
	glweRank int
	// PolyRank is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	polyRank int
	// LogPolyRank equals log(PolyRank).
	logPolyRank int
	// LUTSize is the size of Lookup Table used in Blind Rotation.
	lutSize int
	// LUTExtendFactor equals LUTSize / PolyRank.
	lutExtendFactor int

	// LWEStdDev is the normalized standard deviation used for gaussian error sampling in LWE encryption.
	lweStdDev float64
	// GLWEStdDev is the normalized standard deviation used for gaussian error sampling in GLWE encryption.
	glweStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	blockSize int
	// BlockCount is a number of blocks in LWESecretkey. Equal to LWEDimension / BlockSize.
	blockCount int

	// MessageModulus is the modulus of the encoded message.
	messageModulus T
	// Scale is the scaling factor used for message encoding.
	// The lower log(Scale) bits are reserved for errors.
	scale T

	// logQ is the value of log(Q), where Q is the modulus of the ciphertext.
	logQ int
	// floatQ is the value of Q as float64.
	floatQ float64

	// blindRotateParams is the gadget parameters for Blind Rotation.
	blindRotateParams GadgetParameters[T]
	// keySwitchParams is the gadget parameters for KeySwitching.
	keySwitchParams GadgetParameters[T]

	// bootstrapOrder is the order of Programmable Bootstrapping.
	bootstrapOrder BootstrapOrder
}

// DefaultLWEDimension returns the default dimension for LWE entities.
// Returns LWEDimension if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEDimension otherwise.
func (p Parameters[T]) DefaultLWEDimension() int {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweDimension
	}
	return p.glweDimension
}

// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
func (p Parameters[T]) LWEDimension() int {
	return p.lweDimension
}

// GLWEDimension is the dimension of GLWE lattice used, which is GLWERank * PolyRank.
func (p Parameters[T]) GLWEDimension() int {
	return p.glweDimension
}

// GLWERank is the dimension of GLWE lattice used. Usually this is denoted by k.
// Length of GLWE secret key is GLWERank, and length of GLWE ciphertext is GLWERank+1.
func (p Parameters[T]) GLWERank() int {
	return p.glweRank
}

// PolyRank is the degree of polynomials in GLWE entities. Usually this is denoted by N.
func (p Parameters[T]) PolyRank() int {
	return p.polyRank
}

// LogPolyRank equals log(PolyRank).
func (p Parameters[T]) LogPolyRank() int {
	return p.logPolyRank
}

// LUTSize is the size of LookUpTable used in Blind Rotation.
func (p Parameters[T]) LUTSize() int {
	return p.lutSize
}

// LUTExtendFactor returns LUTSize / PolyRank.
func (p Parameters[T]) LUTExtendFactor() int {
	return p.lutExtendFactor
}

// DefaultLWEStdDev returns the default standard deviation for LWE entities.
// Returns LWEStdDev if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEStdDev otherwise.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.DefaultLWEStdDevQ].
func (p Parameters[T]) DefaultLWEStdDev() float64 {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweStdDev
	}
	return p.glweStdDev
}

// DefaultLWEStdDevQ returns DefaultLWEStdDev * Q.
func (p Parameters[T]) DefaultLWEStdDevQ() float64 {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweStdDev * p.floatQ
	}
	return p.glweStdDev * p.floatQ
}

// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.LWEStdDevQ].
func (p Parameters[T]) LWEStdDev() float64 {
	return p.lweStdDev
}

// LWEStdDevQ returns LWEStdDev * Q.
func (p Parameters[T]) LWEStdDevQ() float64 {
	return p.lweStdDev * p.floatQ
}

// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.GLWEStdDevQ].
func (p Parameters[T]) GLWEStdDev() float64 {
	return p.glweStdDev
}

// GLWEStdDevQ returns GLWEStdDev * Q.
func (p Parameters[T]) GLWEStdDevQ() float64 {
	return p.glweStdDev * p.floatQ
}

// BlockSize is the size of block to be used for LWE key sampling.
func (p Parameters[T]) BlockSize() int {
	return p.blockSize
}

// BlockCount is a number of blocks in LWESecretkey. Equal to LWEDimension / BlockSize.
func (p Parameters[T]) BlockCount() int {
	return p.blockCount
}

// Scale is the scaling factor used for message encoding.
// The lower log(Scale) bits are reserved for errors.
func (p Parameters[T]) Scale() T {
	return p.scale
}

// MessageModulus is the modulus of the encoded message.
func (p Parameters[T]) MessageModulus() T {
	return p.messageModulus
}

// LogQ is the value of log(Q), where Q is the modulus of the ciphertext.
func (p Parameters[T]) LogQ() int {
	return p.logQ
}

// BlindRotateParams is the gadget parameters for Programmable Bootstrapping.
func (p Parameters[T]) BlindRotateParams() GadgetParameters[T] {
	return p.blindRotateParams
}

// KeySwitchParams is the gadget parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParams() GadgetParameters[T] {
	return p.keySwitchParams
}

// BootstrapOrder is the order of Programmable Bootstrapping.
func (p Parameters[T]) BootstrapOrder() BootstrapOrder {
	return p.bootstrapOrder
}

// IsPublicKeyEncryptable returns true if public key encryption is supported.
//
// Currently, public key encryption is supported only with BootstrapOrder OrderKeySwitchBlindRotate.
func (p Parameters[T]) IsPublicKeyEncryptable() bool {
	return p.bootstrapOrder == OrderKeySwitchBlindRotate
}

// Literal returns a ParametersLiteral from this Parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		LWEDimension: p.lweDimension,
		GLWERank:     p.glweRank,
		PolyRank:     p.polyRank,
		LUTSize:      p.lutSize,

		LWEStdDev:  p.lweStdDev,
		GLWEStdDev: p.glweStdDev,

		BlockSize: p.blockSize,

		MessageModulus: p.messageModulus,

		BlindRotateParams: p.blindRotateParams.Literal(),
		KeySwitchParams:   p.keySwitchParams.Literal(),

		BootstrapOrder: p.bootstrapOrder,
	}
}

// EstimateModSwitchStdDev returns an estimated standard deviation of error from modulus switching.
func (p Parameters[T]) EstimateModSwitchStdDev() float64 {
	L := float64(p.lutSize)
	q := p.floatQ

	h := float64(p.blockCount) * (float64(p.blockSize)) / (float64(p.blockSize + 1))

	modSwitchVar := ((h + 1) * q * q) / (48 * L * L)

	return math.Sqrt(modSwitchVar)
}

// EstimateBlindRotateStdDev returns an estimated standard deviation of error from Blind Rotation.
func (p Parameters[T]) EstimateBlindRotateStdDev() float64 {
	n := float64(p.lweDimension)
	k := float64(p.glweRank)
	N := float64(p.polyRank)
	beta := p.GLWEStdDevQ()
	q := p.floatQ

	h := float64(p.blockCount) * (float64(p.blockSize)) / (float64(p.blockSize + 1))

	Bbr := float64(p.blindRotateParams.Base())
	Lbr := float64(p.blindRotateParams.Level())

	blindRotateVar1 := h * (h + (k*N-n)/2 + 1) * (q * q) / (6 * math.Pow(Bbr, 2*Lbr))
	blindRotateVar2 := n * (Lbr * (k + 1) * N * beta * beta * Bbr * Bbr) / 6
	blindRotateFFTVar := n * math.Exp2(-106.6) * (k + 1) * (h + (k*N-n)/2 + 1) * N * (q * q) * Lbr * (Bbr * Bbr)
	blindRotateVar := blindRotateVar1 + blindRotateVar2 + blindRotateFFTVar

	return math.Sqrt(blindRotateVar)
}

// EstimateDefaultKeySwitchStdDev returns an estimated standard deviation of error from Key Switching for bootstrapping.
func (p Parameters[T]) EstimateDefaultKeySwitchStdDev() float64 {
	n := float64(p.lweDimension)
	k := float64(p.glweRank)
	N := float64(p.polyRank)
	alpha := p.LWEStdDevQ()
	q := p.floatQ

	Bks := float64(p.keySwitchParams.Base())
	Lks := float64(p.keySwitchParams.Level())

	keySwitchVar1 := ((k*N - n) / 2) * (q * q) / (12 * math.Pow(Bks, 2*Lks))
	keySwitchVar2 := (k*N - n) * (alpha * alpha * Lks * Bks * Bks) / 12
	keySwitchVar := keySwitchVar1 + keySwitchVar2

	return math.Sqrt(keySwitchVar)
}

// EstimateMaxErrorStdDev returns an estimated standard deviation of maximum possible error.
func (p Parameters[T]) EstimateMaxErrorStdDev() float64 {
	modSwitchStdDev := p.EstimateModSwitchStdDev()
	blindRotateStdDev := p.EstimateBlindRotateStdDev()
	keySwitchStdDev := p.EstimateDefaultKeySwitchStdDev()

	return math.Sqrt(modSwitchStdDev*modSwitchStdDev + blindRotateStdDev*blindRotateStdDev + keySwitchStdDev*keySwitchStdDev)
}

// EstimateFailureProbability returns the failure probability of bootstrapping.
func (p Parameters[T]) EstimateFailureProbability() float64 {
	bound := p.floatQ / (4 * float64(p.messageModulus))
	return math.Erfc(bound / (math.Sqrt2 * p.EstimateMaxErrorStdDev()))
}

// ByteSize returns the byte size of the parameters.
func (p Parameters[T]) ByteSize() int {
	return 8*8 + p.blindRotateParams.ByteSize() + p.keySwitchParams.ByteSize() + 1
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[ 8] LWEDimension
//	[ 8] GLWERank
//	[ 8] PolyRank
//	[ 8] LUTSize
//	[ 8] LWEStdDev
//	[ 8] GLWEStdDev
//	[ 8] BlockSize
//	[ 8] MessageModulus
//	     BlindRotateParameters
//	     KeySwitchParameters
//	[ 1] BootstrapOrder
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var nWrite64 int64
	var buf [8]byte

	lweDimension := p.lweDimension
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	glweRank := p.glweRank
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyRank := p.polyRank
	binary.BigEndian.PutUint64(buf[:], uint64(polyRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	lutSize := p.lutSize
	binary.BigEndian.PutUint64(buf[:], uint64(lutSize))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	lweStdDev := math.Float64bits(p.lweStdDev)
	binary.BigEndian.PutUint64(buf[:], lweStdDev)
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	glweStdDev := math.Float64bits(p.glweStdDev)
	binary.BigEndian.PutUint64(buf[:], glweStdDev)
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	blockSize := p.blockSize
	binary.BigEndian.PutUint64(buf[:], uint64(blockSize))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	messageModulus := uint64(p.messageModulus)
	binary.BigEndian.PutUint64(buf[:], messageModulus)
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if nWrite64, err = p.blindRotateParams.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.keySwitchParams.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	bootstrapOrder := p.bootstrapOrder
	if nWrite, err = w.Write([]byte{byte(bootstrapOrder)}); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if n < int64(p.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (p *Parameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var nRead64 int64
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lutSize := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweStdDev := math.Float64frombits(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	glweStdDev := math.Float64frombits(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	blockSize := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	messageModulus := T(binary.BigEndian.Uint64(buf[:]))

	var blindRotateParams GadgetParameters[T]
	if nRead64, err = blindRotateParams.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	var keySwitchParams GadgetParameters[T]
	if nRead64, err = keySwitchParams.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	if nRead, err = io.ReadFull(r, buf[:1]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	bootstrapOrder := BootstrapOrder(buf[0])

	*p = ParametersLiteral[T]{
		LWEDimension: lweDimension,
		GLWERank:     glweRank,
		PolyRank:     polyRank,
		LUTSize:      lutSize,

		LWEStdDev:  lweStdDev,
		GLWEStdDev: glweStdDev,

		BlockSize: blockSize,

		MessageModulus: messageModulus,

		BlindRotateParams: blindRotateParams.Literal(),
		KeySwitchParams:   keySwitchParams.Literal(),

		BootstrapOrder: bootstrapOrder,
	}.Compile()

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (p Parameters[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, p.ByteSize()))
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (p *Parameters[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := p.ReadFrom(buf)
	return err
}

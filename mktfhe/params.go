package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ParametersLiteral is a multi-key variant of [tfhe.ParametersLiteral].
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T tfhe.TorusInt] struct {
	// PartyCount is the number of maximum parties that this parameter supports.
	PartyCount int

	// SingleLWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	SingleLWEDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	PolyDegree int

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

	// BlindRotateParameters is the gadget parameters for Blind Rotation.
	BlindRotateParameters tfhe.GadgetParametersLiteral[T]
	// KeySwitchParameters is the gadget parameters for KeySwitching.
	KeySwitchParameters tfhe.GadgetParametersLiteral[T]
	// AccumulatorParameters is the gadget parameters for the accumulator.
	AccumulatorParameters tfhe.GadgetParametersLiteral[T]
	// RelinKeyParameters is the gadget parameters for the relinearization key.
	RelinKeyParameters tfhe.GadgetParametersLiteral[T]

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
	BootstrapOrder tfhe.BootstrapOrder
}

// WithPartyCount sets the PartyCount and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPartyCount(partyCount int) ParametersLiteral[T] {
	p.PartyCount = partyCount
	return p
}

// WithSingleLWEDimension sets the LWEDimension and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithSingleLWEDimension(singleLWEDimension int) ParametersLiteral[T] {
	p.SingleLWEDimension = singleLWEDimension
	return p
}

// WithPolyDegree sets the PolyDegree and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPolyDegree(polyDegree int) ParametersLiteral[T] {
	p.PolyDegree = polyDegree
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

// WithBlindRotateParameters sets the BlindRotateParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlindRotateParameters(blindRotateParameters tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.BlindRotateParameters = blindRotateParameters
	return p
}

// WithKeySwitchParameters sets the KeySwitchParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithKeySwitchParameters(keySwitchParameters tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.KeySwitchParameters = keySwitchParameters
	return p
}

// WithAccumulatorParameters sets the AccumulatorParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithAccumulatorParameters(accumulatorParameters tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.AccumulatorParameters = accumulatorParameters
	return p
}

// WithRelinKeyParameters sets the RelinKeyParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithRelinKeyParameters(relinKeyParameters tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.RelinKeyParameters = relinKeyParameters
	return p
}

// WithBootstrapOrder sets the BootstrapOrder and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBootstrapOrder(bootstrapOrder tfhe.BootstrapOrder) ParametersLiteral[T] {
	p.BootstrapOrder = bootstrapOrder
	return p
}

// SingleKeyParametersLiteral extracts the single-key parameters from the multi-key parameters.
func (p ParametersLiteral[T]) SingleKeyParametersLiteral() tfhe.ParametersLiteral[T] {
	return tfhe.ParametersLiteral[T]{
		LWEDimension:    p.SingleLWEDimension,
		GLWERank:        1,
		PolyDegree:      p.PolyDegree,
		LookUpTableSize: p.PolyDegree,

		LWEStdDev:  p.LWEStdDev,
		GLWEStdDev: p.GLWEStdDev,

		BlockSize: p.BlockSize,

		MessageModulus: p.MessageModulus,

		BlindRotateParameters: p.BlindRotateParameters,
		KeySwitchParameters:   p.KeySwitchParameters,

		BootstrapOrder: p.BootstrapOrder,
	}
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
	if p.BlockSize == 0 {
		p.BlockSize = 1
	}

	switch {
	case p.PartyCount <= 0:
		panic("PartyCount smaller than zero")
	case p.SingleLWEDimension > p.PolyDegree:
		panic("LWEDimension larger than GLWEDimension")
	case p.LWEStdDev <= 0:
		panic("LWEStdDev smaller than zero")
	case p.GLWEStdDev <= 0:
		panic("GLWEStdDev smaller than zero")
	case p.BlockSize <= 0:
		panic("BlockSize smaller than zero")
	case p.SingleLWEDimension%p.BlockSize != 0:
		panic("LWEDimension not multiple of BlockSize")
	case !num.IsPowerOfTwo(p.PolyDegree):
		panic("PolyDegree not power of two")
	case !(p.BootstrapOrder == tfhe.OrderKeySwitchBlindRotate || p.BootstrapOrder == tfhe.OrderBlindRotateKeySwitch):
		panic("BootstrapOrder not valid")
	}

	return Parameters[T]{
		singleKeyParameters: p.SingleKeyParametersLiteral().Compile(),

		partyCount: p.PartyCount,

		singleLWEDimension:  p.SingleLWEDimension,
		singleGLWEDimension: p.PolyDegree,
		polyDegree:          p.PolyDegree,

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		blockSize:  p.BlockSize,
		blockCount: p.SingleLWEDimension / p.BlockSize,

		messageModulus: p.MessageModulus,
		scale:          num.DivRound(1<<(num.SizeT[T]()-1), p.MessageModulus),

		logQ:   num.SizeT[T](),
		floatQ: math.Exp2(float64(num.SizeT[T]())),

		blindRotateParameters: p.BlindRotateParameters.Compile(),
		keySwitchParameters:   p.KeySwitchParameters.Compile(),
		accumulatorParameters: p.AccumulatorParameters.Compile(),
		relinKeyParameters:    p.RelinKeyParameters.Compile(),

		bootstrapOrder: p.BootstrapOrder,
	}
}

// Parameters is a read-only multi-key variant of [tfhe.Parameters].
type Parameters[T tfhe.TorusInt] struct {
	// SingleKeyParameters is a single-key Parameters for this multi-key Parameters.
	singleKeyParameters tfhe.Parameters[T]

	// PartyCount is the number of maximum parties
	// that this parameter supports.
	partyCount int

	// SingleLWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	singleLWEDimension int
	// SingleGLWEDimension is the dimension of GLWE lattice used, which is GLWERank * PolyDegree.
	singleGLWEDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	polyDegree int
	// LogPolyDegree equals log(PolyDegree).
	logPolyDegree int

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

	// blindRotateParameters is the gadget parameters for Blind Rotation.
	blindRotateParameters tfhe.GadgetParameters[T]
	// KeySwitchParameters is the gadget parameters for KeySwitching.
	keySwitchParameters tfhe.GadgetParameters[T]
	// AccumulatorParameters is the gadget parameters for the accumulator.
	accumulatorParameters tfhe.GadgetParameters[T]
	// RelinKeyParameters is the gadget parameters for the relinearization key.
	relinKeyParameters tfhe.GadgetParameters[T]

	// bootstrapOrder is the order of Programmable Bootstrapping.
	bootstrapOrder tfhe.BootstrapOrder
}

// PartyCount returns the number of maximum parties
// that this parameter supports.
func (p Parameters[T]) PartyCount() int {
	return p.partyCount
}

// DefaultLWEDimension returns the default dimension of multi-key LWE entities.
func (p Parameters[T]) DefaultLWEDimension() int {
	return p.partyCount * p.SingleDefaultLWEDimension()
}

// LWEDimension returns the dimension of multi-key LWE entities.
func (p Parameters[T]) LWEDimension() int {
	return p.partyCount * p.singleLWEDimension
}

// GLWERank returns the rank of GLWE entities.
// In multi-key TFHE, this is always partyCount.
func (p Parameters[T]) GLWERank() int {
	return p.partyCount
}

// GLWEDimension returns the glwe dimension of multi-key LWE entities.
func (p Parameters[T]) GLWEDimension() int {
	return p.partyCount * p.singleGLWEDimension
}

// SingleKeyDefaultLWEDimension returns the default dimension of single-key LWE entities.
func (p Parameters[T]) SingleDefaultLWEDimension() int {
	if p.bootstrapOrder == tfhe.OrderBlindRotateKeySwitch {
		return p.singleLWEDimension
	}
	return p.singleGLWEDimension
}

// SingleKeyLWEDimension returns the dimension of single-key LWE entities.
func (p Parameters[T]) SingleLWEDimension() int {
	return p.singleLWEDimension
}

// SingleKeyGLWEDimension returns the glwe dimension of single-key LWE entities.
func (p Parameters[T]) SingleGLWEDimension() int {
	return p.singleGLWEDimension
}

// SingleGLWERank returns the rank of single-key GLWE entities.
// In multi-key TFHE, this is always 1.
func (p Parameters[T]) SingleGLWERank() int {
	return 1
}

// PolyDegree returns the degree of polynomials in GLWE entities.
func (p Parameters[T]) PolyDegree() int {
	return p.polyDegree
}

// LogPolyDegree equals log(PolyDegree).
func (p Parameters[T]) LogPolyDegree() int {
	return p.logPolyDegree
}

// DefaultLWEStdDev returns the default standard deviation for LWE entities.
// Returns LWEStdDev if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEStdDev otherwise.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.DefaultLWEStdDevQ].
func (p Parameters[T]) DefaultLWEStdDev() float64 {
	if p.bootstrapOrder == tfhe.OrderBlindRotateKeySwitch {
		return p.lweStdDev
	}
	return p.glweStdDev
}

// DefaultLWEStdDevQ returns DefaultLWEStdDev * Q.
func (p Parameters[T]) DefaultLWEStdDevQ() float64 {
	if p.bootstrapOrder == tfhe.OrderBlindRotateKeySwitch {
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

// BlindRotateParameters is the gadget parameters for Blind Rotation.
func (p Parameters[T]) BlindRotateParameters() tfhe.GadgetParameters[T] {
	return p.blindRotateParameters
}

// KeySwitchParameters is the gadget parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParameters() tfhe.GadgetParameters[T] {
	return p.keySwitchParameters
}

// AccumulatorParameters returns the gadget parameters for the accumulator.
func (p Parameters[T]) AccumulatorParameters() tfhe.GadgetParameters[T] {
	return p.accumulatorParameters
}

// RelinKeyParameters returns the gadget parameters for the relinearization key.
func (p Parameters[T]) RelinKeyParameters() tfhe.GadgetParameters[T] {
	return p.relinKeyParameters
}

// BootstrapOrder is the order of Programmable Bootstrapping.
func (p Parameters[T]) BootstrapOrder() tfhe.BootstrapOrder {
	return p.bootstrapOrder
}

// Literal returns a literal representation of the parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		PartyCount: p.partyCount,

		SingleLWEDimension: p.singleLWEDimension,
		PolyDegree:         p.polyDegree,

		LWEStdDev:  p.lweStdDev,
		GLWEStdDev: p.glweStdDev,

		BlockSize: p.blockSize,

		MessageModulus: p.messageModulus,

		BlindRotateParameters: p.blindRotateParameters.Literal(),
		KeySwitchParameters:   p.keySwitchParameters.Literal(),
		AccumulatorParameters: p.accumulatorParameters.Literal(),
		RelinKeyParameters:    p.relinKeyParameters.Literal(),

		BootstrapOrder: p.bootstrapOrder,
	}
}

// SingleKeyParameters extracts the single-key parameters from the multi-key parameters.
func (p Parameters[T]) SingleKeyParameters() tfhe.Parameters[T] {
	return p.singleKeyParameters
}

// ByteSize returns the size of the parameters in bytes.
func (p Parameters[T]) ByteSize() int {
	return 8*7 + p.blindRotateParameters.ByteSize() + p.keySwitchParameters.ByteSize() + p.accumulatorParameters.ByteSize() + p.relinKeyParameters.ByteSize() + 1
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[ 8] PartyCount
//	[ 8] SingleLWEDimension
//	[ 8] PolyDegree
//	[ 8] LWEStdDev
//	[ 8] GLWEStdDev
//	[ 8] BlockSize
//	[ 8] MessageModulus
//		 BlindRotateParameters
//		 KeySwitchParameters
//	     AccumulatorParameters
//	     RelinKeyParameters
//	[ 1] BootstrapOrder
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var nWrite64 int64
	var buf [8]byte

	partyCount := p.partyCount
	binary.BigEndian.PutUint64(buf[:], uint64(partyCount))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	singleLWEDimension := p.singleLWEDimension
	binary.BigEndian.PutUint64(buf[:], uint64(singleLWEDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := p.polyDegree
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
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

	messageModulus := p.messageModulus
	binary.BigEndian.PutUint64(buf[:], uint64(messageModulus))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if nWrite64, err = p.blindRotateParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.keySwitchParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.accumulatorParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.relinKeyParameters.WriteTo(w); err != nil {
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
	partyCount := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	singleLWEDimension := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

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

	var blindRotateParameters tfhe.GadgetParameters[T]
	if nRead64, err = blindRotateParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	var keySwitchParameters tfhe.GadgetParameters[T]
	if nRead64, err = keySwitchParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	var accumulatorParameters tfhe.GadgetParameters[T]
	if nRead64, err = accumulatorParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	var relinKeyParameters tfhe.GadgetParameters[T]
	if nRead64, err = relinKeyParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	if nRead, err = io.ReadFull(r, buf[:1]); err != nil {
		return n + nRead64, err
	}
	n += int64(nRead)
	bootstrapOrder := tfhe.BootstrapOrder(buf[0])

	*p = ParametersLiteral[T]{
		PartyCount: partyCount,

		SingleLWEDimension: singleLWEDimension,
		PolyDegree:         polyDegree,

		LWEStdDev:  lweStdDev,
		GLWEStdDev: glweStdDev,

		BlockSize: blockSize,

		MessageModulus: messageModulus,

		BlindRotateParameters: blindRotateParameters.Literal(),
		KeySwitchParameters:   keySwitchParameters.Literal(),
		AccumulatorParameters: accumulatorParameters.Literal(),
		RelinKeyParameters:    relinKeyParameters.Literal(),

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

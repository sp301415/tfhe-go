package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/tfhe"
)

// ParametersLiteral is a multi-key variant of [tfhe.ParametersLiteral].
//
// Multi-Key parameters have more restrictions than single-key parameters:
//
//   - GLWERank must be 1.
//   - LookUpTableSize should be equal to PolyDegree.
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T tfhe.TorusInt] struct {
	// SingleKeyParamtersLiteral is the single-key ParametersLiteral for this multi-key Parameters.
	SingleKeyParametersLiteral tfhe.ParametersLiteral[T]

	// PartyCount is the number of maximum parties that this parameter supports.
	PartyCount int

	// AccumulatorParameters is the gadget parameters for the accumulator.
	AccumulatorParameters tfhe.GadgetParametersLiteral[T]
	// RelinKeyParameters is the gadget parameters for the relinearization key.
	RelinKeyParameters tfhe.GadgetParametersLiteral[T]
}

// WithPartyCount sets the PartyCount and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPartyCount(partyCount int) ParametersLiteral[T] {
	p.PartyCount = partyCount
	return p
}

// WithSingleKeyLWEDimension sets the single-key LWEDimension and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithSingleKeyLWEDimension(singleKeyLWEDimension int) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.LWEDimension = singleKeyLWEDimension
	return p
}

// WithPolyDegree sets the PolyDegree and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPolyDegree(polyDegree int) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.PolyDegree = polyDegree
	return p
}

// WithLWEStdDev sets the LWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLWEStdDev(lweStdDev float64) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.LWEStdDev = lweStdDev
	return p
}

// WithGLWEStdDev sets the GLWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithGLWEStdDev(glweStdDev float64) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.GLWEStdDev = glweStdDev
	return p
}

// WithBlockSize sets the BlockSize and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlockSize(blockSize int) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.BlockSize = blockSize
	return p
}

// WithMessageModulus sets the MessageModulus and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithMessageModulus(messageModulus T) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.MessageModulus = messageModulus
	return p
}

// WithBlindRotateParameters sets the BlindRotateParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlindRotateParameters(blindRotateParameters tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.BlindRotateParameters = blindRotateParameters
	return p
}

// WithKeySwitchParameters sets the KeySwitchParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithKeySwitchParameters(keySwitchParameters tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.SingleKeyParametersLiteral.KeySwitchParameters = keySwitchParameters
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
	p.SingleKeyParametersLiteral.BootstrapOrder = bootstrapOrder
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
	switch {
	case p.PartyCount <= 0:
		panic("PartyCount smaller than zero")
	case p.SingleKeyParametersLiteral.GLWERank != 1:
		panic("Multi-Key TFHE only supports GLWE dimension 1")
	case p.SingleKeyParametersLiteral.LookUpTableSize != 0 && p.SingleKeyParametersLiteral.LookUpTableSize != p.SingleKeyParametersLiteral.PolyDegree:
		panic("Multi-Key TFHE only supports LookUpTableSize equal to PolyDegree")
	}

	return Parameters[T]{
		singleKeyParameters: p.SingleKeyParametersLiteral.Compile(),

		partyCount: p.PartyCount,

		accumulatorParameters: p.AccumulatorParameters.Compile(),
		relinKeyParameters:    p.RelinKeyParameters.Compile(),
	}
}

// Parameters is a read-only multi-key variant of [tfhe.Parameters].
type Parameters[T tfhe.TorusInt] struct {
	// SingleKeyParameters is a single-key Parameters for this multi-key Parameters.
	singleKeyParameters tfhe.Parameters[T]

	// PartyCount is the number of maximum parties
	// that this parameter supports.
	partyCount int

	// AccumulatorParameters is the gadget parameters for the accumulator.
	accumulatorParameters tfhe.GadgetParameters[T]
	// RelinKeyParameters is the gadget parameters for the relinearization key.
	relinKeyParameters tfhe.GadgetParameters[T]
}

// PartyCount returns the number of maximum parties
// that this parameter supports.
func (p Parameters[T]) PartyCount() int {
	return p.partyCount
}

// DefaultLWEDimension returns the default dimension of multi-key LWE entities.
func (p Parameters[T]) DefaultLWEDimension() int {
	return p.partyCount * p.singleKeyParameters.DefaultLWEDimension()
}

// LWEDimension returns the dimension of multi-key LWE entities.
func (p Parameters[T]) LWEDimension() int {
	return p.partyCount * p.singleKeyParameters.LWEDimension()
}

// GLWERank returns the rank of GLWE entities.
// In multi-key TFHE, this is always partyCount.
func (p Parameters[T]) GLWERank() int {
	return p.partyCount
}

// GLWEDimension returns the glwe dimension of multi-key LWE entities.
func (p Parameters[T]) GLWEDimension() int {
	return p.partyCount * p.singleKeyParameters.GLWEDimension()
}

// PolyDegree returns the degree of polynomials in GLWE entities.
func (p Parameters[T]) PolyDegree() int {
	return p.singleKeyParameters.PolyDegree()
}

// LogPolyDegree equals log(PolyDegree).
func (p Parameters[T]) LogPolyDegree() int {
	return p.singleKeyParameters.LogPolyDegree()
}

// DefaultLWEStdDev returns the default standard deviation for LWE entities.
// Returns LWEStdDev if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEStdDev otherwise.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.DefaultLWEStdDevQ].
func (p Parameters[T]) DefaultLWEStdDev() float64 {
	return p.singleKeyParameters.DefaultLWEStdDev()
}

// DefaultLWEStdDevQ returns DefaultLWEStdDev * Q.
func (p Parameters[T]) DefaultLWEStdDevQ() float64 {
	return p.singleKeyParameters.DefaultLWEStdDevQ()
}

// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.LWEStdDevQ].
func (p Parameters[T]) LWEStdDev() float64 {
	return p.singleKeyParameters.LWEStdDev()
}

// LWEStdDevQ returns LWEStdDev * Q.
func (p Parameters[T]) LWEStdDevQ() float64 {
	return p.singleKeyParameters.LWEStdDevQ()
}

// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.GLWEStdDevQ].
func (p Parameters[T]) GLWEStdDev() float64 {
	return p.singleKeyParameters.GLWEStdDev()
}

// GLWEStdDevQ returns GLWEStdDev * Q.
func (p Parameters[T]) GLWEStdDevQ() float64 {
	return p.singleKeyParameters.GLWEStdDevQ()
}

// BlockSize is the size of block to be used for LWE key sampling.
func (p Parameters[T]) BlockSize() int {
	return p.singleKeyParameters.BlockSize()
}

// BlockCount is a number of blocks in LWESecretkey. Equal to LWEDimension / BlockSize.
func (p Parameters[T]) BlockCount() int {
	return p.singleKeyParameters.BlockCount()
}

// Scale is the scaling factor used for message encoding.
// The lower log(Scale) bits are reserved for errors.
func (p Parameters[T]) Scale() T {
	return p.singleKeyParameters.Scale()
}

// MessageModulus is the modulus of the encoded message.
func (p Parameters[T]) MessageModulus() T {
	return p.singleKeyParameters.MessageModulus()
}

// LogQ is the value of log(Q), where Q is the modulus of the ciphertext.
func (p Parameters[T]) LogQ() int {
	return p.singleKeyParameters.LogQ()
}

// BlindRotateParameters is the gadget parameters for Blind Rotation.
func (p Parameters[T]) BlindRotateParameters() tfhe.GadgetParameters[T] {
	return p.singleKeyParameters.BlindRotateParameters()
}

// KeySwitchParameters is the gadget parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParameters() tfhe.GadgetParameters[T] {
	return p.singleKeyParameters.KeySwitchParameters()
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
	return p.singleKeyParameters.BootstrapOrder()
}

// Literal returns a literal representation of the parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		SingleKeyParametersLiteral: p.singleKeyParameters.Literal(),

		PartyCount: p.partyCount,

		AccumulatorParameters: p.accumulatorParameters.Literal(),
		RelinKeyParameters:    p.relinKeyParameters.Literal(),
	}
}

// SingleKeyParameters extracts the single-key parameters from the multi-key parameters.
func (p Parameters[T]) SingleKeyParameters() tfhe.Parameters[T] {
	return p.singleKeyParameters
}

// ByteSize returns the size of the parameters in bytes.
func (p Parameters[T]) ByteSize() int {
	return p.singleKeyParameters.ByteSize() + 8 + p.accumulatorParameters.ByteSize() + p.relinKeyParameters.ByteSize()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//		 SingleKeyParameters
//	[ 8] PartyCount
//	     AccumulatorParameters
//	     RelinKeyParameters
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var nWrite64 int64
	var buf [8]byte

	if nWrite64, err = p.singleKeyParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	partyCount := p.partyCount
	binary.BigEndian.PutUint64(buf[:], uint64(partyCount))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if nWrite64, err = p.accumulatorParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.relinKeyParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

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

	if nRead64, err = p.singleKeyParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	partyCount := int(binary.BigEndian.Uint64(buf[:]))

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

	*p = ParametersLiteral[T]{
		SingleKeyParametersLiteral: p.singleKeyParameters.Literal(),

		PartyCount: partyCount,

		AccumulatorParameters: accumulatorParameters.Literal(),
		RelinKeyParameters:    relinKeyParameters.Literal(),
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

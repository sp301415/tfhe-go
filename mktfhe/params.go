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
//   - LUTSize should be equal to PolyRank.
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T tfhe.TorusInt] struct {
	// SubParams is the single-key ParametersLiteral for this multi-key Parameters.
	SubParams tfhe.ParametersLiteral[T]

	// PartyCount is the number of maximum parties that this parameter supports.
	PartyCount int

	// AccumulatorParams is the gadget parameters for the accumulator.
	AccumulatorParams tfhe.GadgetParametersLiteral[T]
	// RelinKeyParams is the gadget parameters for the relinearization key.
	RelinKeyParams tfhe.GadgetParametersLiteral[T]
}

// WithPartyCount sets the PartyCount and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPartyCount(partyCount int) ParametersLiteral[T] {
	p.PartyCount = partyCount
	return p
}

// WithSingleKeyLWEDimension sets the single-key LWEDimension and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithSingleKeyLWEDimension(singleKeyLWEDimension int) ParametersLiteral[T] {
	p.SubParams.LWEDimension = singleKeyLWEDimension
	return p
}

// WithPolyRank sets the PolyRank and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPolyRank(polyRank int) ParametersLiteral[T] {
	p.SubParams.PolyRank = polyRank
	return p
}

// WithLWEStdDev sets the LWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLWEStdDev(lweStdDev float64) ParametersLiteral[T] {
	p.SubParams.LWEStdDev = lweStdDev
	return p
}

// WithGLWEStdDev sets the GLWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithGLWEStdDev(glweStdDev float64) ParametersLiteral[T] {
	p.SubParams.GLWEStdDev = glweStdDev
	return p
}

// WithBlockSize sets the BlockSize and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlockSize(blockSize int) ParametersLiteral[T] {
	p.SubParams.BlockSize = blockSize
	return p
}

// WithMessageModulus sets the MessageModulus and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithMessageModulus(messageModulus T) ParametersLiteral[T] {
	p.SubParams.MessageModulus = messageModulus
	return p
}

// WithBlindRotateParams sets the BlindRotateParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlindRotateParams(blindRotateParams tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.SubParams.BlindRotateParams = blindRotateParams
	return p
}

// WithKeySwitchParams sets the KeySwitchParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithKeySwitchParams(keySwitchParams tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.SubParams.KeySwitchParams = keySwitchParams
	return p
}

// WithAccumulatorParams sets the AccumulatorParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithAccumulatorParams(accumulatorParams tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.AccumulatorParams = accumulatorParams
	return p
}

// WithRelinKeyParams sets the RelinKeyParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithRelinKeyParams(relinKeyParams tfhe.GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.RelinKeyParams = relinKeyParams
	return p
}

// WithBootstrapOrder sets the BootstrapOrder and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBootstrapOrder(bootstrapOrder tfhe.BootstrapOrder) ParametersLiteral[T] {
	p.SubParams.BootstrapOrder = bootstrapOrder
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
	subParams := p.SubParams.Compile()

	switch {
	case p.PartyCount <= 0:
		panic("Compile: PartyCount smaller than zero")
	case subParams.GLWERank() != 1:
		panic("Compile: Multi-Key TFHE only supports GLWE dimension 1")
	case subParams.LUTSize() != subParams.PolyRank():
		panic("Compile: Multi-Key TFHE only supports LUTSize equal to PolyRank")
	}

	return Parameters[T]{
		subParams: subParams,

		partyCount: p.PartyCount,

		accumulatorParams: p.AccumulatorParams.Compile(),
		relinKeyParams:    p.RelinKeyParams.Compile(),
	}
}

// Parameters is a read-only multi-key variant of [tfhe.Parameters].
type Parameters[T tfhe.TorusInt] struct {
	// SingleKeyParameters is a single-key Parameters for this multi-key Parameters.
	subParams tfhe.Parameters[T]

	// PartyCount is the number of maximum parties
	// that this parameter supports.
	partyCount int

	// AccumulatorParams is the gadget parameters for the accumulator.
	accumulatorParams tfhe.GadgetParameters[T]
	// RelinKeyParams is the gadget parameters for the relinearization key.
	relinKeyParams tfhe.GadgetParameters[T]
}

// PartyCount returns the number of maximum parties
// that this parameter supports.
func (p Parameters[T]) PartyCount() int {
	return p.partyCount
}

// DefaultLWEDimension returns the default dimension of multi-key LWE entities.
func (p Parameters[T]) DefaultLWEDimension() int {
	return p.partyCount * p.subParams.DefaultLWEDimension()
}

// LWEDimension returns the dimension of multi-key LWE entities.
func (p Parameters[T]) LWEDimension() int {
	return p.partyCount * p.subParams.LWEDimension()
}

// GLWERank returns the rank of GLWE entities.
// In multi-key TFHE, this is always partyCount.
func (p Parameters[T]) GLWERank() int {
	return p.partyCount
}

// GLWEDimension returns the glwe dimension of multi-key LWE entities.
func (p Parameters[T]) GLWEDimension() int {
	return p.partyCount * p.subParams.GLWEDimension()
}

// PolyRank returns the degree of polynomials in GLWE entities.
func (p Parameters[T]) PolyRank() int {
	return p.subParams.PolyRank()
}

// LogPolyRank equals log(PolyRank).
func (p Parameters[T]) LogPolyRank() int {
	return p.subParams.LogPolyRank()
}

// DefaultLWEStdDev returns the default standard deviation for LWE entities.
// Returns LWEStdDev if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEStdDev otherwise.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.DefaultLWEStdDevQ].
func (p Parameters[T]) DefaultLWEStdDev() float64 {
	return p.subParams.DefaultLWEStdDev()
}

// DefaultLWEStdDevQ returns DefaultLWEStdDev * Q.
func (p Parameters[T]) DefaultLWEStdDevQ() float64 {
	return p.subParams.DefaultLWEStdDevQ()
}

// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.LWEStdDevQ].
func (p Parameters[T]) LWEStdDev() float64 {
	return p.subParams.LWEStdDev()
}

// LWEStdDevQ returns LWEStdDev * Q.
func (p Parameters[T]) LWEStdDevQ() float64 {
	return p.subParams.LWEStdDevQ()
}

// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
//
// This is a normalized standard deviation.
// For actual sampling, use [Parameters.GLWEStdDevQ].
func (p Parameters[T]) GLWEStdDev() float64 {
	return p.subParams.GLWEStdDev()
}

// GLWEStdDevQ returns GLWEStdDev * Q.
func (p Parameters[T]) GLWEStdDevQ() float64 {
	return p.subParams.GLWEStdDevQ()
}

// BlockSize is the size of block to be used for LWE key sampling.
func (p Parameters[T]) BlockSize() int {
	return p.subParams.BlockSize()
}

// BlockCount is a number of blocks in LWESecretkey. Equal to LWEDimension / BlockSize.
func (p Parameters[T]) BlockCount() int {
	return p.subParams.BlockCount()
}

// Scale is the scaling factor used for message encoding.
// The lower log(Scale) bits are reserved for errors.
func (p Parameters[T]) Scale() T {
	return p.subParams.Scale()
}

// MessageModulus is the modulus of the encoded message.
func (p Parameters[T]) MessageModulus() T {
	return p.subParams.MessageModulus()
}

// LogQ is the value of log(Q), where Q is the modulus of the ciphertext.
func (p Parameters[T]) LogQ() int {
	return p.subParams.LogQ()
}

// BlindRotateParams is the gadget parameters for Blind Rotation.
func (p Parameters[T]) BlindRotateParams() tfhe.GadgetParameters[T] {
	return p.subParams.BlindRotateParams()
}

// KeySwitchParams is the gadget parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParams() tfhe.GadgetParameters[T] {
	return p.subParams.KeySwitchParams()
}

// AccumulatorParameters returns the gadget parameters for the accumulator.
func (p Parameters[T]) AccumulatorParameters() tfhe.GadgetParameters[T] {
	return p.accumulatorParams
}

// RelinKeyParameters returns the gadget parameters for the relinearization key.
func (p Parameters[T]) RelinKeyParameters() tfhe.GadgetParameters[T] {
	return p.relinKeyParams
}

// BootstrapOrder is the order of Programmable Bootstrapping.
func (p Parameters[T]) BootstrapOrder() tfhe.BootstrapOrder {
	return p.subParams.BootstrapOrder()
}

// Literal returns a literal representation of the parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		SubParams: p.subParams.Literal(),

		PartyCount: p.partyCount,

		AccumulatorParams: p.accumulatorParams.Literal(),
		RelinKeyParams:    p.relinKeyParams.Literal(),
	}
}

// SubParams extracts the single-key parameters from the multi-key parameters.
func (p Parameters[T]) SubParams() tfhe.Parameters[T] {
	return p.subParams
}

// ByteSize returns the size of the parameters in bytes.
func (p Parameters[T]) ByteSize() int {
	return p.subParams.ByteSize() + 8 + p.accumulatorParams.ByteSize() + p.relinKeyParams.ByteSize()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//		 SubParameters
//	[ 8] PartyCount
//	     AccumulatorParameters
//	     RelinKeyParameters
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var nWrite64 int64
	var buf [8]byte

	if nWrite64, err = p.subParams.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	partyCount := p.partyCount
	binary.BigEndian.PutUint64(buf[:], uint64(partyCount))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if nWrite64, err = p.accumulatorParams.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.relinKeyParams.WriteTo(w); err != nil {
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

	if nRead64, err = p.subParams.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	partyCount := int(binary.BigEndian.Uint64(buf[:]))

	var accumulatorParams tfhe.GadgetParameters[T]
	if nRead64, err = accumulatorParams.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	var relinKeyParams tfhe.GadgetParameters[T]
	if nRead64, err = relinKeyParams.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	*p = ParametersLiteral[T]{
		SubParams: p.subParams.Literal(),

		PartyCount: partyCount,

		AccumulatorParams: accumulatorParams.Literal(),
		RelinKeyParams:    relinKeyParams.Literal(),
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

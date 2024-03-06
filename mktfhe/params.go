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
//   - GLWEDimension must be 1.
//   - PolyLargeDegree should be equal to PolyDegree.
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T tfhe.TorusInt] struct {
	// ParametersLiteral is an embedded [tfhe.ParametersLiteral].
	tfhe.ParametersLiteral[T]

	// PartyCount is the number of maximum parties
	// that this parameter supports.
	PartyCount int

	// AccumulatorParameters is the gadget parameters for the accumulator.
	AccumulatorParameters tfhe.GadgetParametersLiteral[T]

	// RelinKeyParameters is the gadget parameters for the relinearization key.
	RelinKeyParameters tfhe.GadgetParametersLiteral[T]
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
	case p.GLWEDimension != 1:
		panic("Multi-Key TFHE only supports GLWE dimension 1")
	case p.PolyLargeDegree != p.PolyDegree:
		panic("Multi-Key TFHE only supports PolyLargeDegree equal to PolyDegree")
	}

	return Parameters[T]{
		Parameters: p.ParametersLiteral.Compile(),

		partyCount: p.PartyCount,

		accumulatorParameters: p.AccumulatorParameters.Compile(),
		relinKeyParameters:    p.RelinKeyParameters.Compile(),
	}
}

// Parameters is a read-only multi-key variant of [tfhe.Parameters].
type Parameters[T tfhe.TorusInt] struct {
	// Parameter is an embedded [tfhe.Parameters].
	tfhe.Parameters[T]

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
	return p.partyCount * p.Parameters.DefaultLWEDimension()
}

// LWEDimension returns the dimension of multi-key LWE entities.
func (p Parameters[T]) LWEDimension() int {
	return p.partyCount * p.Parameters.LWEDimension()
}

// LWELargeDimension returns the large dimension of multi-key LWE entities.
func (p Parameters[T]) LWELargeDimension() int {
	return p.partyCount * p.Parameters.LWELargeDimension()
}

// SingleKeyDefaultLWEDimension returns the default dimension of single-key LWE entities.
func (p Parameters[T]) SingleKeyDefaultLWEDimension() int {
	return p.Parameters.DefaultLWEDimension()
}

// SingleKeyLWEDimension returns the dimension of single-key LWE entities.
func (p Parameters[T]) SingleKeyLWEDimension() int {
	return p.Parameters.LWEDimension()
}

// SingleKeyLWELargeDimension returns the large dimension of single-key LWE entities.
func (p Parameters[T]) SingleKeyLWELargeDimension() int {
	return p.Parameters.LWELargeDimension()
}

// GLWEDimension returns the dimension of multi-key GLWE entities.
func (p Parameters[T]) GLWEDimension() int {
	return p.partyCount * p.Parameters.GLWEDimension()
}

// SingleKeyGLWEDimension returns the dimension of single-key GLWE entities.
func (p Parameters[T]) SingleKeyGLWEDimension() int {
	return p.Parameters.GLWEDimension()
}

// AccumulatorParameters returns the gadget parameters for the accumulator.
func (p Parameters[T]) AccumulatorParameters() tfhe.GadgetParameters[T] {
	return p.accumulatorParameters
}

// RelinKeyParameters returns the gadget parameters for the relinearization key.
func (p Parameters[T]) RelinKeyParameters() tfhe.GadgetParameters[T] {
	return p.relinKeyParameters
}

// Literal returns a literal representation of the parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		ParametersLiteral: p.Parameters.Literal(),

		PartyCount: p.partyCount,

		AccumulatorParameters: p.accumulatorParameters.Literal(),
		RelinKeyParameters:    p.relinKeyParameters.Literal(),
	}
}

// ByteSize returns the size of the parameters in bytes.
func (p Parameters[T]) ByteSize() int {
	return p.Parameters.ByteSize() + 8 + 2*16
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//		  Parameters
//	 [ 8] PartyCount
//	 [16] AccumulatorParameters
//	 [16] RelinKeyParameters
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn64 int64
	var nn int

	nn64, err = p.Parameters.WriteTo(w)
	n += nn64
	if err != nil {
		return
	}

	var buf [8 + 2*16]byte

	binary.BigEndian.PutUint64(buf[0:8], uint64(p.partyCount))
	binary.BigEndian.PutUint64(buf[8:16], uint64(p.accumulatorParameters.Base()))
	binary.BigEndian.PutUint64(buf[16:24], uint64(p.accumulatorParameters.Level()))
	binary.BigEndian.PutUint64(buf[24:32], uint64(p.relinKeyParameters.Base()))
	binary.BigEndian.PutUint64(buf[32:40], uint64(p.relinKeyParameters.Level()))

	nn, err = w.Write(buf[:])
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
	var nn64 int64
	var nn int

	nn64, err = p.Parameters.ReadFrom(r)
	n += nn64
	if err != nil {
		return
	}

	var buf [8 + 2*16]byte

	nn, err = io.ReadFull(r, buf[:])
	n += int64(nn)
	if err != nil {
		return
	}

	partyCount := binary.BigEndian.Uint64(buf[0:8])

	accumulatorParameters := tfhe.GadgetParametersLiteral[T]{
		Base:  T(binary.BigEndian.Uint64(buf[8:16])),
		Level: int(binary.BigEndian.Uint64(buf[16:24])),
	}
	relinKeyParameters := tfhe.GadgetParametersLiteral[T]{
		Base:  T(binary.BigEndian.Uint64(buf[24:32])),
		Level: int(binary.BigEndian.Uint64(buf[32:40])),
	}

	*p = ParametersLiteral[T]{
		ParametersLiteral: p.Parameters.Literal(),

		PartyCount: int(partyCount),

		AccumulatorParameters: accumulatorParameters,
		RelinKeyParameters:    relinKeyParameters,
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
	buf := bytes.NewBuffer(data)
	_, err := p.ReadFrom(buf)
	return err
}

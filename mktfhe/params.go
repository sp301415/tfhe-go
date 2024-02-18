package mktfhe

import (
	"bytes"
	"io"

	"github.com/sp301415/tfhe-go/tfhe"
)

// ParametersLiteral is a Multi-Key variant of TFHE parameters literal.
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T tfhe.TorusInt] struct {
	// ParametersLiteral is an embedded TFHE parameters literal.
	tfhe.ParametersLiteral[T]

	// PartyCount is the number of maximum parties
	// that this parameter supports.
	PartyCount int
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
func (p *ParametersLiteral[T]) Compile() *Parameters[T] {
	switch {
	case p.PartyCount <= 0:
		panic("PartyCount smaller than zero")
	}

	return &Parameters[T]{
		Parameters: p.ParametersLiteral.Compile(),

		partyCount: p.PartyCount,
	}
}

// Parameters is a read-only Multi-Key variant of TFHE parameters.
type Parameters[T tfhe.TorusInt] struct {
	// Parameter is an embedded TFHE parameters.
	tfhe.Parameters[T]

	partyCount int
}

// PartyCount returns the number of maximum parties
// that this parameter supports.
func (p Parameters[T]) PartyCount() int {
	return p.partyCount
}

// DefaultLWEDimension returns the default dimension of Multi-Key LWE entities.
func (p Parameters[T]) DefaultLWEDimension() int {
	return p.partyCount * p.Parameters.DefaultLWEDimension()
}

// LWEDimension returns the dimension of Multi-Key LWE entities.
func (p Parameters[T]) LWEDimension() int {
	return p.partyCount * p.Parameters.LWEDimension()
}

// LWELargeDimension returns the large dimension of Multi-Key LWE entities.
func (p Parameters[T]) LWELargeDimension() int {
	return p.partyCount * p.Parameters.LWELargeDimension()
}

// GLWEDimension returns the dimension of Multi-Key GLWE entities.
func (p Parameters[T]) GLWEDimension() int {
	return p.partyCount * p.Parameters.GLWEDimension()
}

// Literal returns a literal representation of the parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		ParametersLiteral: p.Parameters.Literal(),

		PartyCount: p.partyCount,
	}
}

// ByteSize returns the size of the parameters in bytes.
func (p Parameters[T]) ByteSize() int {
	return p.Parameters.ByteSize() + 4
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	    Parameters
//	[8] PartyCount
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	// TODO: NOT IMPLEMENTED
	panic("not implemented")
}

// ReadFrom implements the io.ReaderFrom interface.
func (p *Parameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	// TODO: NOT IMPLEMENTED
	panic("not implemented")
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

package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ByteSize returns the size of the ciphertext in bytes.
func (ct GLWECiphertext[T]) ByteSize() int {
	glweDimension := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	return 16 + (glweDimension+1)*polyDegree*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] GLWEDimension
//	[8] PolyDegree
//	    Value
func (ct GLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	glweDimension := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(glweDimension))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, p := range ct.Value {
			for i := range p.Coeffs {
				binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(p.Coeffs[i]))
			}

			nn, err = w.Write(buf)
			n += int64(nn)
			if err != nil {
				return
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, p := range ct.Value {
			for i := range p.Coeffs {
				binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(p.Coeffs[i]))
			}

			nn, err = w.Write(buf)
			n += int64(nn)
			if err != nil {
				return
			}
		}
	}

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (ct *GLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweDimension := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*ct = NewGLWECiphertextCustom[T](glweDimension, polyDegree)

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, p := range ct.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range p.Coeffs {
				p.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, p := range ct.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range p.Coeffs {
				p.Coeffs[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
			}
		}
	}

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (ct GLWECiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (ct *GLWECiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct UniEncryption[T]) ByteSize() int {
	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	return 24 + 2*level*2*polyDegree*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
//	[8] PolyDegree
//	    Value
func (ct UniEncryption[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(ct.GadgetParameters.Base()))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
				for _, p := range glwe.Value {
					for i := range p.Coeffs {
						binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(p.Coeffs[i]))
					}

					nn, err = w.Write(buf)
					n += int64(nn)
					if err != nil {
						return
					}
				}
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
				for _, p := range glwe.Value {
					for i := range p.Coeffs {
						binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(p.Coeffs[i]))
					}

					nn, err = w.Write(buf)
					n += int64(nn)
					if err != nil {
						return
					}
				}
			}
		}
	}

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (ct *UniEncryption[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [24]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[16:24]))

	*ct = NewUniEncryptionCustom[T](polyDegree, tfhe.GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
				for _, p := range glwe.Value {
					nn, err = io.ReadFull(r, buf)
					n += int64(nn)
					if err != nil {
						return
					}

					for i := range p.Coeffs {
						p.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
					}
				}
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
				for _, p := range glwe.Value {
					nn, err = io.ReadFull(r, buf)
					n += int64(nn)
					if err != nil {
						return
					}

					for i := range p.Coeffs {
						p.Coeffs[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
					}
				}
			}
		}
	}

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (ct UniEncryption[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (ct *UniEncryption[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

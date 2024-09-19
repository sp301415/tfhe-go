package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/tfhe"
)

// floatVecWriteToBuffered implements the [io.WriterTo] interface for a vector of float64, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func floatVecWriteToBuffered(v []float64, buf []byte, w io.Writer) (n int64, err error) {
	var nWrite int

	for i := range v {
		binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], math.Float64bits(v[i]))
	}

	nWrite, err = w.Write(buf)
	return int64(nWrite), err
}

// floatVecReadFromBuffered implements the [io.ReaderFrom] interface for a vector of float64, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func floatVecReadFromBuffered(v []float64, buf []byte, r io.Reader) (n int64, err error) {
	var nRead int

	if nRead, err = io.ReadFull(r, buf); err != nil {
		return int64(nRead), err
	}
	n += int64(nRead)

	for i := range v {
		v[i] = math.Float64frombits(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
	}

	return
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct FourierGLWECiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	return 16 + (glweRank+1)*polyDegree*8
}

// headerWriteTo writes the header.
func (ct FourierGLWECiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ct.Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct FourierGLWECiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range ct.Value {
		if nWrite, err = floatVecWriteToBuffered(ct.Value[i].Coeffs, buf, w); err != nil {
			return n + nWrite, err
		}
		n += nWrite
	}

	return
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct FourierGLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = ct.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = ct.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (ct *FourierGLWECiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return int64(nRead), err
	}
	n += int64(nRead)
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewFourierGLWECiphertextCustom[T](glweRank, polyDegree)

	return
}

// valueReadFrom reads the value.
func (ct FourierGLWECiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range ct.Value {
		if nRead, err = floatVecReadFromBuffered(ct.Value[i].Coeffs, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FourierGLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = ct.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = ct.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct FourierGLWECiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FourierGLWECiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct FourierUniEncryption[T]) ByteSize() int {
	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	return 24 + 2*level*2*polyDegree*8
}

// headerWriteTo writes the header.
func (ct FourierUniEncryption[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ct.GadgetParameters.Base()
	binary.BigEndian.PutUint64(buf[:], uint64(base))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := len(ct.Value[0].Value)
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct FourierUniEncryption[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nWrite, err = floatVecWriteToBuffered(ct.Value[i].Value[j].Value[k].Coeffs, buf, w); err != nil {
					return n + nWrite, err
				}
				n += nWrite
			}
		}
	}

	return
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
//	[8] PolyDegree
//	    Value
func (ct FourierUniEncryption[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = ct.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = ct.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (ct *FourierUniEncryption[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewFourierUniEncryptionCustom(polyDegree, tfhe.GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *FourierUniEncryption[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nRead, err = floatVecReadFromBuffered(ct.Value[i].Value[j].Value[k].Coeffs, buf, r); err != nil {
					return n + nRead, err
				}
				n += nRead
			}
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FourierUniEncryption[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = ct.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = ct.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct FourierUniEncryption[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FourierUniEncryption[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

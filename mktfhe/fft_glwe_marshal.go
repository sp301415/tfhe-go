package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/tfhe"
)

// floatVecWriteToBuf implements the [io.WriterTo] interface for a vector of float64, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func floatVecWriteToBuf(v []float64, buf []byte, w io.Writer) (n int64, err error) {
	var nWrite int

	for i := range v {
		binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], math.Float64bits(v[i]))
	}

	nWrite, err = w.Write(buf)
	return int64(nWrite), err
}

// floatVecReadFromBuf implements the [io.ReaderFrom] interface for a vector of float64, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func floatVecReadFromBuf(v []float64, buf []byte, r io.Reader) (n int64, err error) {
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
func (ct FFTGLWECiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	polyRank := ct.Value[0].Rank()

	return 16 + (glweRank+1)*polyRank*8
}

// headerWriteTo writes the header.
func (ct FFTGLWECiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	polyRank := ct.Value[0].Rank()
	binary.BigEndian.PutUint64(buf[:], uint64(polyRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct FFTGLWECiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyRank := ct.Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range ct.Value {
		if nWrite, err = floatVecWriteToBuf(ct.Value[i].Coeffs, buf, w); err != nil {
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
//	[8] PolyRank
//	    Value
func (ct FFTGLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *FFTGLWECiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	polyRank := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewFFTGLWECiphertextCustom[T](glweRank, polyRank)

	return
}

// valueReadFrom reads the value.
func (ct FFTGLWECiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyRank := ct.Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range ct.Value {
		if nRead, err = floatVecReadFromBuf(ct.Value[i].Coeffs, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FFTGLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct FFTGLWECiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FFTGLWECiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct FFTUniEncryption[T]) ByteSize() int {
	level := len(ct.Value[0].Value)
	polyRank := ct.Value[0].Value[0].Value[0].Rank()

	return 24 + 2*level*2*polyRank*8
}

// headerWriteTo writes the header.
func (ct FFTUniEncryption[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ct.GadgetParams.Base()
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

	polyRank := ct.Value[0].Value[0].Value[0].Rank()
	binary.BigEndian.PutUint64(buf[:], uint64(polyRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct FFTUniEncryption[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyRank := ct.Value[0].Value[0].Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nWrite, err = floatVecWriteToBuf(ct.Value[i].Value[j].Value[k].Coeffs, buf, w); err != nil {
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
//	[8] PolyRank
//	    Value
func (ct FFTUniEncryption[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *FFTUniEncryption[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	polyRank := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewFFTUniEncryptionCustom(polyRank, tfhe.GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *FFTUniEncryption[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyRank := ct.Value[0].Value[0].Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nRead, err = floatVecReadFromBuf(ct.Value[i].Value[j].Value[k].Coeffs, buf, r); err != nil {
					return n + nRead, err
				}
				n += nRead
			}
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FFTUniEncryption[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct FFTUniEncryption[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FFTUniEncryption[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

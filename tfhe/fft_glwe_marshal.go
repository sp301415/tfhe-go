package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
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

// ByteSize returns the size of the key in bytes.
func (sk FFTGLWESecretKey[T]) ByteSize() int {
	glweRank := len(sk.Value)
	polyRank := sk.Value[0].Rank()

	return 16 + glweRank*polyRank*8
}

// headerWriteTo writes the header.
func (sk FFTGLWESecretKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(sk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	polyRank := sk.Value[0].Rank()
	binary.BigEndian.PutUint64(buf[:], uint64(polyRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (sk FFTGLWESecretKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyRank := sk.Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range sk.Value {
		if nWrite, err = floatVecWriteToBuf(sk.Value[i].Coeffs, buf, w); err != nil {
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
func (sk FFTGLWESecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = sk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = sk.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(sk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (sk *FFTGLWESecretKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*sk = NewFFTGLWESecretKeyCustom[T](glweRank, polyRank)

	return
}

// valueReadFrom reads the value.
func (sk *FFTGLWESecretKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyRank := sk.Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range sk.Value {
		if nRead, err = floatVecReadFromBuf(sk.Value[i].Coeffs, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (sk *FFTGLWESecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = sk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = sk.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (sk FFTGLWESecretKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, sk.ByteSize()))
	_, err = sk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (sk *FFTGLWESecretKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := sk.ReadFrom(buf)
	return err
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
func (ct FFTGLevCiphertext[T]) ByteSize() int {
	level := len(ct.Value)
	glweRank := len(ct.Value[0].Value) - 1
	polyRank := ct.Value[0].Value[0].Rank()

	return 32 + level*(glweRank+1)*polyRank*8
}

// headerWriteTo writes the header.
func (ct FFTGLevCiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ct.GadgetParams.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	level := len(ct.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	glweRank := len(ct.Value[0].Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	polyRank := ct.Value[0].Value[0].Rank()
	binary.BigEndian.PutUint64(buf[:], uint64(polyRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct FFTGLevCiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyRank := ct.Value[0].Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			if nWrite, err = floatVecWriteToBuf(ct.Value[i].Value[j].Coeffs, buf, w); err != nil {
				return n + nWrite, err
			}
			n += nWrite
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
//	[8] GLWERank
//	[8] PolyRank
//	    Value
func (ct FFTGLevCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *FFTGLevCiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyRank := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewFFTGLevCiphertextCustom(glweRank, polyRank, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct FFTGLevCiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyRank := ct.Value[0].Value[0].Rank()
	buf := make([]byte, polyRank*8)

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			if nRead, err = floatVecReadFromBuf(ct.Value[i].Value[j].Coeffs, buf, r); err != nil {
				return n + nRead, err
			}
			n += nRead
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FFTGLevCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct FFTGLevCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FFTGLevCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct FFTGGSWCiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	level := len(ct.Value[0].Value)
	polyRank := ct.Value[0].Value[0].Value[0].Rank()

	return 32 + (glweRank+1)*level*(glweRank+1)*polyRank*8
}

// headerWriteTo writes the header.
func (ct FFTGGSWCiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ct.GadgetParams.base
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

	glweRank := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
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
func (ct FFTGGSWCiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
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
//	[8] GLWERank
//	[8] PolyRank
//	    Value
func (ct FFTGGSWCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *FFTGGSWCiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyRank := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewFFTGGSWCiphertextCustom(glweRank, polyRank, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct FFTGGSWCiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
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
func (ct *FFTGGSWCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct FFTGGSWCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FFTGGSWCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

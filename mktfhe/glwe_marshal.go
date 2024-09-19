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
	glweRank := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	return 16 + (glweRank+1)*polyDegree*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (ct GLWECiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ct.Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct GLWECiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for _, p := range ct.Value {
		if nWrite, err = vecWriteToBuffered(p.Coeffs, buf, w); err != nil {
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
func (ct GLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *GLWECiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewGLWECiphertextCustom[T](glweRank, polyDegree)

	return
}

// valueReadFrom reads the value.
func (ct *GLWECiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for _, p := range ct.Value {
		if nRead, err = vecReadFromBuffered(p.Coeffs, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct GLWECiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *GLWECiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct UniEncryption[T]) ByteSize() int {
	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	return 24 + 2*level*2*polyDegree*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (ct UniEncryption[T]) headerWriteTo(w io.Writer) (n int64, err error) {
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
func (ct UniEncryption[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nWrite, err = vecWriteToBuffered(ct.Value[i].Value[j].Value[k].Coeffs, buf, w); err != nil {
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
func (ct UniEncryption[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *UniEncryption[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*ct = NewUniEncryptionCustom(polyDegree, tfhe.GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *UniEncryption[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nRead, err = vecReadFromBuffered(ct.Value[i].Value[j].Value[k].Coeffs, buf, r); err != nil {
					return n + nRead, err
				}
				n += nRead
			}
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *UniEncryption[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct UniEncryption[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *UniEncryption[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

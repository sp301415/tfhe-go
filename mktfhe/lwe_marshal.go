package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// vecWriteTo implements the [io.WriterTo] interface for a vector of T.
func vecWriteTo[T tfhe.TorusInt](v []T, w io.Writer) (n int64, err error) {
	var nWrite int

	var z T
	switch any(z).(type) {
	case uint32:
		var buf [4]byte
		for i := range v {
			binary.BigEndian.PutUint32(buf[:], uint32(v[i]))
			if nWrite, err = w.Write(buf[:]); err != nil {
				return n + int64(nWrite), err
			}
			n += int64(nWrite)
		}
	case uint64:
		var buf [8]byte
		for i := range v {
			binary.BigEndian.PutUint64(buf[:], uint64(v[i]))
			if nWrite, err = w.Write(buf[:]); err != nil {
				return n + int64(nWrite), err
			}
			n += int64(nWrite)
		}
	}
	return
}

// vecWriteToBuf implements the [io.WriterTo] interface for a vector of T, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func vecWriteToBuf[T tfhe.TorusInt](v []T, buf []byte, w io.Writer) (n int64, err error) {
	var nWrite int

	var z T
	switch any(z).(type) {
	case uint32:
		for i := range v {
			binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(v[i]))
		}
		if nWrite, err = w.Write(buf); err != nil {
			return n + int64(nWrite), err
		}
		n += int64(nWrite)

	case uint64:
		for i := range v {
			binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(v[i]))
		}
		if nWrite, err = w.Write(buf); err != nil {
			return n + int64(nWrite), err
		}
		n += int64(nWrite)
	}
	return
}

// vecReadFrom implements the [io.ReaderFrom] interface for a vector of T.
func vecReadFrom[T tfhe.TorusInt](v []T, r io.Reader) (n int64, err error) {
	var nRead int

	var z T
	switch any(z).(type) {
	case uint32:
		var buf [4]byte
		for i := range v {
			if nRead, err = io.ReadFull(r, buf[:]); err != nil {
				return n + int64(nRead), err
			}
			n += int64(nRead)
			v[i] = T(binary.BigEndian.Uint32(buf[:]))
		}

	case uint64:
		var buf [8]byte
		for i := range v {
			if nRead, err = io.ReadFull(r, buf[:]); err != nil {
				return n + int64(nRead), err
			}
			n += int64(nRead)
			v[i] = T(binary.BigEndian.Uint64(buf[:]))
		}
	}

	return
}

// vecReadFromBuf implements the [io.ReaderFrom] interface for a vector of T, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func vecReadFromBuf[T tfhe.TorusInt](v []T, buf []byte, r io.Reader) (n int64, err error) {
	var nRead int

	var z T
	switch any(z).(type) {
	case uint32:
		if nRead, err = io.ReadFull(r, buf); err != nil {
			return n + int64(nRead), err
		}
		n += int64(nRead)

		for i := range v {
			v[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
		}

	case uint64:
		if nRead, err = io.ReadFull(r, buf); err != nil {
			return n + int64(nRead), err
		}
		n += int64(nRead)

		for i := range v {
			v[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
		}
	}

	return
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct LWECiphertext[T]) ByteSize() int {
	return 8 + len(ct.Value)*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (ct LWECiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	lweDimension := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct LWECiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	return vecWriteTo(ct.Value, w)
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] LWEDimension
//	    Value
func (ct LWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *LWECiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewLWECiphertextCustom[T](lweDimension)

	return
}

// valueReadFrom reads the value.
func (ct *LWECiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	return vecReadFrom(ct.Value, r)
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *LWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
func (ct LWECiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *LWECiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

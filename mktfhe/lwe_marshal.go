package mktfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the ciphertext in bytes.
func (ct LWECiphertext[T]) ByteSize() int {
	return 8 + len(ct.Value)*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] LWEDimension
//	    Value
func (ct LWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	lweDimension := len(ct.Value) - 1

	var metadata [8]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(lweDimension))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (lweDimension+1)*4)
		for i := range ct.Value {
			binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(ct.Value[i]))
		}

		nn, err = w.Write(buf)
		n += int64(nn)
		if err != nil {
			return
		}

	case uint64:
		buf := make([]byte, (lweDimension+1)*8)
		for i := range ct.Value {
			binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(ct.Value[i]))
		}

		nn, err = w.Write(buf)
		n += int64(nn)
		if err != nil {
			return
		}
	}

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *LWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [8]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	lweDimension := int(binary.BigEndian.Uint64(metadata[0:8]))

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (lweDimension+1)*4)
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		*ct = NewLWECiphertextCustom[T](lweDimension)
		for i := range ct.Value {
			ct.Value[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
		}

	case uint64:
		buf := make([]byte, (lweDimension+1)*8)
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		*ct = NewLWECiphertextCustom[T](lweDimension)
		for i := range ct.Value {
			ct.Value[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
		}
	}

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

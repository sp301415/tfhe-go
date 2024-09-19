package mktfhe

import (
	"bytes"
	"io"
)

// ByteSize returns the size of the key in bytes.
func (evk EvaluationKey[T]) ByteSize() int {
	return evk.EvaluationKey.ByteSize() + evk.CRSPublicKey.ByteSize() + evk.RelinKey.ByteSize()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	EvaluationKey
//	CRSPublicKey
//	RelinKey
func (evk EvaluationKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = evk.EvaluationKey.WriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = evk.CRSPublicKey.WriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = evk.RelinKey.WriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(evk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (evk *EvaluationKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = evk.EvaluationKey.ReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = evk.CRSPublicKey.ReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = evk.RelinKey.ReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if n < int64(evk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (evk EvaluationKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, evk.ByteSize()))
	_, err = evk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (evk *EvaluationKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := evk.ReadFrom(buf)
	return err
}

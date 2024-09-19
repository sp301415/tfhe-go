package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the key in bytes.
func (sk SecretKey[T]) ByteSize() int {
	glweRank := len(sk.GLWEKey.Value)
	polyDegree := sk.GLWEKey.Value[0].Degree()

	return 24 + glweRank*polyDegree*num.ByteSizeT[T]() + glweRank*polyDegree*8
}

// headerWriteTo writes the header.
func (sk SecretKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	lweDimension := len(sk.LWEKey.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	glweRank := len(sk.GLWEKey.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := sk.GLWEKey.Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] LWEDimension
//	[8] GLWERank
//	[8] PolyDegree
//	    LWELargeKey
//	    FourierGLWEKey
func (sk SecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = sk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = sk.LWELargeKey.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = sk.FourierGLWEKey.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(sk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (sk *SecretKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

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

	*sk = NewSecretKeyCustom[T](lweDimension, glweRank, polyDegree)

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (sk *SecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = sk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = sk.LWELargeKey.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = sk.FourierGLWEKey.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (sk SecretKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, sk.ByteSize()))
	_, err = sk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (sk *SecretKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := sk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the key in bytes.
func (pk PublicKey[T]) ByteSize() int {
	return pk.LWEKey.ByteSize() + pk.GLWEKey.ByteSize()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	LWEKey
//	GLWEKey
func (pk PublicKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = pk.LWEKey.WriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = pk.GLWEKey.WriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(pk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pk *PublicKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = pk.LWEKey.ReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = pk.GLWEKey.ReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (pk PublicKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, pk.ByteSize()))
	_, err = pk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (pk *PublicKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := pk.ReadFrom(buf)
	return err
}

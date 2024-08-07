package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the key in bytes.
func (sk SecretKey[T]) ByteSize() int {
	glweRank := len(sk.GLWEKey.Value)
	polyDegree := sk.GLWEKey.Value[0].Degree()

	return 24 + glweRank*polyDegree*num.ByteSizeT[T]() + glweRank*polyDegree*8
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
	var nn int

	lweDimension := len(sk.LWEKey.Value)
	glweRank := len(sk.GLWEKey.Value)
	polyDegree := sk.GLWEKey.Value[0].Degree()

	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(lweDimension))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(glweRank))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	buf := make([]byte, polyDegree*8)

	var z T
	switch any(z).(type) {
	case uint32:
		for _, p := range sk.GLWEKey.Value {
			for i := range p.Coeffs {
				binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(p.Coeffs[i]))
			}

			nn, err = w.Write(buf[:polyDegree*4])
			n += int64(nn)
			if err != nil {
				return
			}
		}

	case uint64:
		for _, p := range sk.GLWEKey.Value {
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

	for _, fp := range sk.FourierGLWEKey.Value {
		for i := range fp.Coeffs {
			binary.BigEndian.PutUint64(buf[(i+0)*8:(i+1)*8], math.Float64bits(fp.Coeffs[i]))
		}

		nn, err = w.Write(buf)
		n += int64(nn)
		if err != nil {
			return
		}
	}

	if n < int64(sk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (sk *SecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [24]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	lweDimension := int(binary.BigEndian.Uint64(metadata[0:8]))
	glweRank := int(binary.BigEndian.Uint64(metadata[8:16]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[16:24]))

	*sk = NewSecretKeyCustom[T](lweDimension, glweRank, polyDegree)

	buf := make([]byte, polyDegree*8)

	var z T
	switch any(z).(type) {
	case uint32:
		for _, p := range sk.GLWEKey.Value {
			nn, err = io.ReadFull(r, buf[:polyDegree*4])
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range p.Coeffs {
				p.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
			}
		}

	case uint64:
		for _, p := range sk.GLWEKey.Value {
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

	for _, fp := range sk.FourierGLWEKey.Value {
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		for i := range fp.Coeffs {
			fp.Coeffs[i] = math.Float64frombits(binary.BigEndian.Uint64(buf[(i+0)*8 : (i+1)*8]))
		}
	}

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
	var nn int64

	nn, err = pk.LWEKey.WriteTo(w)
	n += int64(nn)
	if err != nil {
		return
	}

	nn, err = pk.GLWEKey.WriteTo(w)
	n += int64(nn)
	if err != nil {
		return
	}

	if n < int64(pk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pk *PublicKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int64

	nn, err = pk.LWEKey.ReadFrom(r)
	n += int64(nn)
	if err != nil {
		return
	}

	nn, err = pk.GLWEKey.ReadFrom(r)
	n += int64(nn)
	if err != nil {
		return
	}

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

package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// SecretKey is a structure containing LWE and GLWE key.
//
// LWEKey and GLWEKey is sampled together, as explained in https://eprint.iacr.org/2023/958.
// As a result, LWEKey and GLWEKey share the same backing slice, so modifying one will affect the other.
type SecretKey[T Tint] struct {
	// LWELargeKey is a LWE key with length LWELargeDimension.
	// Essentially, this is same as GLWEKey but parsed differently.
	LWELargeKey LWEKey[T]
	// GLWEKey is a key used for GLWE encryption and decryption.
	// Essentially, this is same as LWEKey but parsed differently.
	GLWEKey GLWEKey[T]
	// FourierGLWEKey is a fourier transformed GLWEKey.
	// Used for GLWE encryption.
	FourierGLWEKey FourierGLWEKey[T]
	// LWEKey is a LWE key with length LWEDimension.
	// Essentially, this is the first LWEDimension elements of LWEKey.
	LWEKey LWEKey[T]
}

// NewSecretKey allocates an empty secret key.
// Each key shares the same backing slice, held by LWEKey.
func NewSecretKey[T Tint](params Parameters[T]) SecretKey[T] {
	lweLargeKey := LWEKey[T]{Value: make([]T, params.lweLargeDimension)}

	glweKey := GLWEKey[T]{Value: make([]poly.Poly[T], params.glweDimension)}
	for i := 0; i < params.glweDimension; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*params.polyDegree : (i+1)*params.polyDegree]
	}
	fourierGLWEKey := NewFourierGLWEKey(params)

	lweKey := LWEKey[T]{Value: lweLargeKey.Value[:params.lweDimension]}

	return SecretKey[T]{
		LWELargeKey:    lweLargeKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWEKey:         lweKey,
	}
}

// NewSecretKeyCustom allocates an empty secret key with given dimension and polyDegree.
// Each key shares the same backing slice, held by LWEKey.
func NewSecretKeyCustom[T Tint](lweDimension, glweDimension, polyDegree int) SecretKey[T] {
	lweLargeKey := LWEKey[T]{Value: make([]T, glweDimension*polyDegree)}

	glweKey := GLWEKey[T]{Value: make([]poly.Poly[T], glweDimension)}
	for i := 0; i < glweDimension; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*polyDegree : (i+1)*polyDegree]
	}
	fourierGLWEKey := NewFourierGLWEKeyCustom[T](glweDimension, polyDegree)

	lweKey := LWEKey[T]{Value: lweLargeKey.Value[:lweDimension]}

	return SecretKey[T]{
		LWELargeKey:    lweLargeKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWEKey:         lweKey,
	}
}

// Copy returns a copy of the key.
func (sk SecretKey[T]) Copy() SecretKey[T] {
	lweLargeKey := sk.LWELargeKey.Copy()

	glweKey := GLWEKey[T]{Value: make([]poly.Poly[T], len(sk.GLWEKey.Value))}
	for i := range glweKey.Value {
		polyDegree := sk.GLWEKey.Value[i].Degree()
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*polyDegree : (i+1)*polyDegree]
	}
	fourierGLWEKey := sk.FourierGLWEKey.Copy()

	lweKey := LWEKey[T]{Value: lweLargeKey.Value[:len(sk.LWEKey.Value)]}

	return SecretKey[T]{
		LWELargeKey:    lweLargeKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWEKey:         lweKey,
	}
}

// CopyFrom copies values from a key.
func (sk *SecretKey[T]) CopyFrom(skIn SecretKey[T]) {
	vec.CopyAssign(skIn.LWELargeKey.Value, sk.LWELargeKey.Value)
	sk.FourierGLWEKey.CopyFrom(skIn.FourierGLWEKey)
}

// Clear clears the key.
func (sk *SecretKey[T]) Clear() {
	vec.Fill(sk.LWELargeKey.Value, 0)
	sk.FourierGLWEKey.Clear()
}

// ByteSize returns the size of the key in bytes.
func (sk SecretKey[T]) ByteSize() int {
	glweDimension := len(sk.GLWEKey.Value)
	polyDegree := sk.GLWEKey.Value[0].Degree()

	return 24 + glweDimension*polyDegree*(num.SizeT[T]()/8) + glweDimension*polyDegree*8
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	           8               8            8
//	LWEDimension | GLWEDimension | PolyDegree | LWELargeKey | FourierGLWEKey
func (sk SecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	lweDimension := len(sk.LWEKey.Value)
	glweDimension := len(sk.GLWEKey.Value)
	polyDegree := sk.GLWEKey.Value[0].Degree()

	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(lweDimension))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(glweDimension))
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
		for i, b := 0, 0; i < len(fp.Coeffs); i, b = i+1, b+2 {
			binary.BigEndian.PutUint64(buf[(b+0)*8:(b+1)*8], math.Float64bits(real(fp.Coeffs[i])))
			binary.BigEndian.PutUint64(buf[(b+1)*8:(b+2)*8], math.Float64bits(imag(fp.Coeffs[i])))
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

// ReadFrom implements the io.ReaderFrom interface.
func (sk *SecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [24]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	lweDimension := int(binary.BigEndian.Uint64(metadata[0:8]))
	glweDimension := int(binary.BigEndian.Uint64(metadata[8:16]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[16:24]))

	*sk = NewSecretKeyCustom[T](lweDimension, glweDimension, polyDegree)

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

		for i, b := 0, 0; i < len(fp.Coeffs); i, b = i+1, b+2 {
			fp.Coeffs[i] = complex(
				math.Float64frombits(binary.BigEndian.Uint64(buf[(b+0)*8:(b+1)*8])),
				math.Float64frombits(binary.BigEndian.Uint64(buf[(b+1)*8:(b+2)*8])),
			)
		}
	}

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (sk SecretKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, sk.ByteSize()))
	_, err = sk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (sk *SecretKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := sk.ReadFrom(buf)
	return err
}

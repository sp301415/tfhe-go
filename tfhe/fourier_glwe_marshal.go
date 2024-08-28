package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
)

// ByteSize returns the size of the key in bytes.
func (sk FourierGLWESecretKey[T]) ByteSize() int {
	glweRank := len(sk.Value)
	polyDegree := sk.Value[0].Degree()

	return 16 + glweRank*polyDegree*8
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (sk FourierGLWESecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	glweRank := len(sk.Value)
	polyDegree := sk.Value[0].Degree()

	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(glweRank))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	buf := make([]byte, polyDegree*8)

	for _, p := range sk.Value {
		for i := range p.Coeffs {
			binary.BigEndian.PutUint64(buf[(i+0)*8:(i+1)*8], math.Float64bits(p.Coeffs[i]))
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
func (sk *FourierGLWESecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweRank := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*sk = NewFourierGLWESecretKeyCustom[T](glweRank, polyDegree)

	buf := make([]byte, polyDegree*8)

	for _, p := range sk.Value {
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		for i := range p.Coeffs {
			p.Coeffs[i] = math.Float64frombits(binary.BigEndian.Uint64(buf[(i+0)*8 : (i+1)*8]))
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (sk FourierGLWESecretKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, sk.ByteSize()))
	_, err = sk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (sk *FourierGLWESecretKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := sk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct FourierGLWECiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	return 16 + (glweRank+1)*polyDegree*8
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct FourierGLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	glweRank := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(glweRank))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	buf := make([]byte, polyDegree*8)

	for _, p := range ct.Value {
		for i := range p.Coeffs {
			binary.BigEndian.PutUint64(buf[(i+0)*8:(i+1)*8], math.Float64bits(p.Coeffs[i]))
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
func (ct *FourierGLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweRank := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*ct = NewFourierGLWECiphertextCustom[T](glweRank, polyDegree)

	buf := make([]byte, polyDegree*8)

	for _, p := range ct.Value {
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		for i := range p.Coeffs {
			p.Coeffs[i] = math.Float64frombits(binary.BigEndian.Uint64(buf[(i+0)*8 : (i+1)*8]))
		}
	}

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
func (ct FourierGLevCiphertext[T]) ByteSize() int {
	level := len(ct.Value)
	glweRank := len(ct.Value[0].Value) - 1
	polyDegree := ct.Value[0].Value[0].Degree()

	return 32 + level*(glweRank+1)*polyDegree*8
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct FourierGLevCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	level := len(ct.Value)
	glweRank := len(ct.Value[0].Value) - 1
	polyDegree := ct.Value[0].Value[0].Degree()

	var metadata [32]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(ct.GadgetParameters.base))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(glweRank))
	binary.BigEndian.PutUint64(metadata[24:32], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	buf := make([]byte, polyDegree*8)

	for _, fglwe := range ct.Value {
		for _, p := range fglwe.Value {
			for i := range p.Coeffs {
				binary.BigEndian.PutUint64(buf[(i+0)*8:(i+1)*8], math.Float64bits(p.Coeffs[i]))
			}

			nn, err = w.Write(buf)
			n += int64(nn)
			if err != nil {
				return
			}
		}
	}

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FourierGLevCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [32]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	glweRank := int(binary.BigEndian.Uint64(metadata[16:24]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[24:32]))

	*ct = NewFourierGLevCiphertextCustom(glweRank, polyDegree, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	buf := make([]byte, polyDegree*8)

	for _, c := range ct.Value {
		for _, p := range c.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range p.Coeffs {
				p.Coeffs[i] = math.Float64frombits(binary.BigEndian.Uint64(buf[(i+0)*8 : (i+1)*8]))
			}
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct FourierGLevCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FourierGLevCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct FourierGGSWCiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	return 32 + (glweRank+1)*level*(glweRank+1)*polyDegree*8
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct FourierGGSWCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	glweRank := len(ct.Value) - 1
	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	var metadata [32]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(ct.GadgetParameters.base))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(glweRank))
	binary.BigEndian.PutUint64(metadata[24:32], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	buf := make([]byte, polyDegree*8)

	for _, fglev := range ct.Value {
		for _, fglwe := range fglev.Value {
			for _, p := range fglwe.Value {
				for i := range p.Coeffs {
					binary.BigEndian.PutUint64(buf[(i+0)*8:(i+1)*8], math.Float64bits(p.Coeffs[i]))
				}

				nn, err = w.Write(buf)
				n += int64(nn)
				if err != nil {
					return
				}
			}
		}
	}

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *FourierGGSWCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [32]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	glweRank := int(binary.BigEndian.Uint64(metadata[16:24]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[24:32]))

	*ct = NewFourierGGSWCiphertextCustom(glweRank, polyDegree, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	buf := make([]byte, polyDegree*8)

	for _, fglev := range ct.Value {
		for _, fglwe := range fglev.Value {
			for _, p := range fglwe.Value {
				nn, err = io.ReadFull(r, buf)
				n += int64(nn)
				if err != nil {
					return
				}

				for i := range p.Coeffs {
					p.Coeffs[i] = math.Float64frombits(binary.BigEndian.Uint64(buf[(i+0)*8 : (i+1)*8]))
				}
			}
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct FourierGGSWCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *FourierGGSWCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

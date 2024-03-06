package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the key in bytes.
func (sk LWESecretKey[T]) ByteSize() int {
	return 8 + len(sk.Value)*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] LWEDimension
//	    Value
func (sk LWESecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	lweDimension := len(sk.Value)

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
		buf := make([]byte, lweDimension*4)
		for i := range sk.Value {
			binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(sk.Value[i]))
		}

		nn, err = w.Write(buf)
		n += int64(nn)
		if err != nil {
			return
		}

	case uint64:
		buf := make([]byte, lweDimension*8)
		for i := range sk.Value {
			binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(sk.Value[i]))
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
func (sk *LWESecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
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
		buf := make([]byte, lweDimension*4)
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		*sk = NewLWESecretKeyCustom[T](lweDimension)
		for i := range sk.Value {
			sk.Value[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
		}

	case uint64:
		buf := make([]byte, lweDimension*8)
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		*sk = NewLWESecretKeyCustom[T](lweDimension)
		for i := range sk.Value {
			sk.Value[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (sk LWESecretKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, sk.ByteSize()))
	_, err = sk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (sk *LWESecretKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := sk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the key in bytes.
func (pk LWEPublicKey[T]) ByteSize() int {
	glweDimension := len(pk.Value)
	polyDegree := pk.Value[0].Value[0].Degree()
	return 16 + glweDimension*(glweDimension+1)*polyDegree*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] GLWEDimension
//	[8] PolyDegree
//	    Value
func (pk LWEPublicKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	glweDimension := len(pk.Value)
	polyDegree := pk.Value[0].Value[0].Degree()

	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(glweDimension))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glwe := range pk.Value {
			for _, p := range glwe.Value {
				for i := range p.Coeffs {
					binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(p.Coeffs[i]))
				}

				nn, err = w.Write(buf)
				n += int64(nn)
				if err != nil {
					return
				}
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, glwe := range pk.Value {
			for _, p := range glwe.Value {
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
	}

	if n < int64(pk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pk *LWEPublicKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweDimension := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*pk = NewLWEPublicKeyCustom[T](glweDimension, polyDegree)

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glwe := range pk.Value {
			for _, p := range glwe.Value {
				nn, err = io.ReadFull(r, buf)
				n += int64(nn)
				if err != nil {
					return
				}

				for i := range p.Coeffs {
					p.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
				}
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, glwe := range pk.Value {
			for _, p := range glwe.Value {
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
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (pk LWEPublicKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, pk.ByteSize()))
	_, err = pk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (pk *LWEPublicKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	_, err := pk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the plaintext in bytes.
func (pt LWEPlaintext[T]) ByteSize() int {
	return num.SizeT[T]() / 8
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	Value
func (pt LWEPlaintext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	var z T
	switch any(z).(type) {
	case uint32:
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(pt.Value))
		nn, err = w.Write(buf[:])
		n += int64(nn)
		if err != nil {
			return
		}

	case uint64:
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(pt.Value))
		nn, err = w.Write(buf[:])
		n += int64(nn)
		if err != nil {
			return
		}
	}

	if n < int64(pt.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pt *LWEPlaintext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var z T
	switch any(z).(type) {
	case uint32:
		var buf [4]byte
		nn, err = io.ReadFull(r, buf[:])
		n += int64(nn)
		if err != nil {
			return
		}

		pt.Value = T(binary.BigEndian.Uint32(buf[:]))

	case uint64:
		var buf [8]byte
		nn, err = io.ReadFull(r, buf[:])
		n += int64(nn)
		if err != nil {
			return
		}

		pt.Value = T(binary.BigEndian.Uint64(buf[:]))
	}

	if n < int64(pt.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (pt LWEPlaintext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, pt.ByteSize()))
	_, err = pt.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (pt *LWEPlaintext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := pt.ReadFrom(buf)
	return err
}

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

// ByteSize returns the size of the ciphertext in bytes.
func (ct LevCiphertext[T]) ByteSize() int {
	level := len(ct.Value)
	lweDimension := len(ct.Value[0].Value) - 1

	return 24 + level*(lweDimension+1)*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
//	[8] LWEDimension
//	    Value
func (ct LevCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	level := len(ct.Value)
	lweDimension := len(ct.Value[0].Value) - 1

	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(ct.GadgetParameters.base))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(lweDimension))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (lweDimension+1)*4)

		for _, lwe := range ct.Value {
			for i := range lwe.Value {
				binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(lwe.Value[i]))
			}

			nn, err = w.Write(buf)
			n += int64(nn)
			if err != nil {
				return
			}
		}

	case uint64:
		buf := make([]byte, (lweDimension+1)*8)

		for _, lwe := range ct.Value {
			for i := range lwe.Value {
				binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(lwe.Value[i]))
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
func (ct *LevCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [24]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	lweDimension := int(binary.BigEndian.Uint64(metadata[16:24]))

	*ct = NewLevCiphertextCustom[T](lweDimension, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (lweDimension+1)*4)

		for _, lwe := range ct.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range lwe.Value {
				lwe.Value[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
			}
		}

	case uint64:
		buf := make([]byte, (lweDimension+1)*8)

		for _, lwe := range ct.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range lwe.Value {
				lwe.Value[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
			}
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct LevCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *LevCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct GSWCiphertext[T]) ByteSize() int {
	lweDimension := len(ct.Value) - 1
	level := len(ct.Value[0].Value)

	return 24 + (lweDimension+1)*level*(lweDimension+1)*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
//	[8] LWEDimension
//	    Value
func (ct GSWCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	lweDimension := len(ct.Value) - 1
	level := len(ct.Value[0].Value)

	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(ct.GadgetParameters.base))
	binary.BigEndian.PutUint64(metadata[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadata[16:24], uint64(lweDimension))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (lweDimension+1)*4)

		for _, lev := range ct.Value {
			for _, lwe := range lev.Value {
				for i := range lwe.Value {
					binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(lwe.Value[i]))
				}

				nn, err = w.Write(buf)
				n += int64(nn)
				if err != nil {
					return
				}
			}
		}

	case uint64:
		buf := make([]byte, (lweDimension+1)*8)

		for _, lev := range ct.Value {
			for _, lwe := range lev.Value {
				for i := range lwe.Value {
					binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(lwe.Value[i]))
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
func (ct *GSWCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [24]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	lweDimension := int(binary.BigEndian.Uint64(metadata[16:24]))

	*ct = NewGSWCiphertextCustom[T](lweDimension, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (lweDimension+1)*4)

		for _, lev := range ct.Value {
			for _, lwe := range lev.Value {
				nn, err = io.ReadFull(r, buf)
				n += int64(nn)
				if err != nil {
					return
				}

				for i := range lwe.Value {
					lwe.Value[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
				}
			}
		}

	case uint64:
		buf := make([]byte, (lweDimension+1)*8)

		for _, lev := range ct.Value {
			for _, lwe := range lev.Value {
				nn, err = io.ReadFull(r, buf)
				n += int64(nn)
				if err != nil {
					return
				}

				for i := range lwe.Value {
					lwe.Value[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
				}
			}
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct GSWCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *GSWCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

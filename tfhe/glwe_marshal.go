package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the key in bytes.
func (sk GLWESecretKey[T]) ByteSize() int {
	glweRank := len(sk.Value)
	polyDegree := sk.Value[0].Degree()

	return 16 + glweRank*polyDegree*num.ByteSizeT[T]()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (sk GLWESecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
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

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, p := range sk.Value {
			for i := range p.Coeffs {
				binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(p.Coeffs[i]))
			}

			nn, err = w.Write(buf)
			n += int64(nn)
			if err != nil {
				return
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, p := range sk.Value {
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

	if n < int64(sk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (sk *GLWESecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweRank := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*sk = NewGLWESecretKeyCustom[T](glweRank, polyDegree)

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, p := range sk.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range p.Coeffs {
				p.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, p := range sk.Value {
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

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (sk GLWESecretKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, sk.ByteSize()))
	_, err = sk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (sk *GLWESecretKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := sk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the key in bytes.
func (pk GLWEPublicKey[T]) ByteSize() int {
	glweRank := len(pk.Value)
	polyDegree := pk.Value[0].Value[0].Degree()

	return 16 + glweRank*(glweRank+1)*polyDegree*num.ByteSizeT[T]()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (pk GLWEPublicKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	glweRank := len(pk.Value)
	polyDegree := pk.Value[0].Value[0].Degree()

	var metadata [16]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(glweRank))
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
func (pk *GLWEPublicKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweRank := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*pk = NewGLWEPublicKeyCustom[T](glweRank, polyDegree)

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
func (pk GLWEPublicKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, pk.ByteSize()))
	_, err = pk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (pk *GLWEPublicKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := pk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the plaintext in bytes.
func (pt GLWEPlaintext[T]) ByteSize() int {
	polyDegree := pt.Value.Degree()

	return 8 + polyDegree*num.ByteSizeT[T]()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] PolyDegree
//	    Value
func (pt GLWEPlaintext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	polyDegree := pt.Value.Degree()

	var metadata [8]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(polyDegree))
	nn, err = w.Write(metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for i := range pt.Value.Coeffs {
			binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(pt.Value.Coeffs[i]))
		}

		nn, err = w.Write(buf)
		n += int64(nn)
		if err != nil {
			return
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for i := range pt.Value.Coeffs {
			binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(pt.Value.Coeffs[i]))
		}

		nn, err = w.Write(buf)
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
func (pt *GLWEPlaintext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [8]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	polyDegree := int(binary.BigEndian.Uint64(metadata[0:8]))

	*pt = NewGLWEPlaintextCustom[T](polyDegree)

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		for i := range pt.Value.Coeffs {
			pt.Value.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
		}

	case uint64:
		buf := make([]byte, polyDegree*8)
		nn, err = io.ReadFull(r, buf)
		n += int64(nn)
		if err != nil {
			return
		}

		for i := range pt.Value.Coeffs {
			pt.Value.Coeffs[i] = T(binary.BigEndian.Uint64(buf[i*8 : (i+1)*8]))
		}
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (pt GLWEPlaintext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, pt.ByteSize()))
	_, err = pt.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (pt *GLWEPlaintext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := pt.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct GLWECiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	polyDegree := ct.Value[0].Degree()

	return 16 + (glweRank+1)*polyDegree*num.ByteSizeT[T]()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct GLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, p := range ct.Value {
			for i := range p.Coeffs {
				binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(p.Coeffs[i]))
			}

			nn, err = w.Write(buf)
			n += int64(nn)
			if err != nil {
				return
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, p := range ct.Value {
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

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [16]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	glweRank := int(binary.BigEndian.Uint64(metadata[0:8]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[8:16]))

	*ct = NewGLWECiphertextCustom[T](glweRank, polyDegree)

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, p := range ct.Value {
			nn, err = io.ReadFull(r, buf)
			n += int64(nn)
			if err != nil {
				return
			}

			for i := range p.Coeffs {
				p.Coeffs[i] = T(binary.BigEndian.Uint32(buf[i*4 : (i+1)*4]))
			}
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, p := range ct.Value {
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
func (ct GLevCiphertext[T]) ByteSize() int {
	level := len(ct.Value)
	glweRank := len(ct.Value[0].Value) - 1
	polyDegree := ct.Value[0].Value[0].Degree()

	return 32 + level*(glweRank+1)*polyDegree*num.ByteSizeT[T]()
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
func (ct GLevCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glwe := range ct.Value {
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

		for _, glwe := range ct.Value {
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

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GLevCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

	*ct = NewGLevCiphertextCustom[T](glweRank, polyDegree, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glwe := range ct.Value {
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

		for _, glwe := range ct.Value {
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
func (ct GLevCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *GLevCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the ciphertext in bytes.
func (ct GGSWCiphertext[T]) ByteSize() int {
	glweRank := len(ct.Value) - 1
	level := len(ct.Value[0].Value)
	polyDegree := ct.Value[0].Value[0].Value[0].Degree()

	return 32 + (glweRank+1)*level*(glweRank+1)*polyDegree*num.ByteSizeT[T]()
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
func (ct GGSWCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
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
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
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
	}

	if n < int64(ct.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GGSWCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

	*ct = NewGGSWCiphertextCustom[T](glweRank, polyDegree, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, polyDegree*4)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
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
		}

	case uint64:
		buf := make([]byte, polyDegree*8)

		for _, glev := range ct.Value {
			for _, glwe := range glev.Value {
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
	}

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ct GGSWCiphertext[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ct.ByteSize()))
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ct *GGSWCiphertext[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ct.ReadFrom(buf)
	return err
}

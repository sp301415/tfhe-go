package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
)

// vecWriteTo implements the [io.WriterTo] interface for a vector of T.
func vecWriteTo[T TorusInt](v []T, w io.Writer) (n int64, err error) {
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

// vecWriteToBuffered implements the [io.WriterTo] interface for a vector of T, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func vecWriteToBuffered[T TorusInt](v []T, buf []byte, w io.Writer) (n int64, err error) {
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
func vecReadFrom[T TorusInt](v []T, r io.Reader) (n int64, err error) {
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

// vecReadFromBuffered implements the [io.ReaderFrom] interface for a vector of T, using a buffer.
// Assumes the length of the buffer is exactly the byte length of v.
func vecReadFromBuffered[T TorusInt](v []T, buf []byte, r io.Reader) (n int64, err error) {
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

// ByteSize returns the size of the key in bytes.
func (sk LWESecretKey[T]) ByteSize() int {
	return 8 + len(sk.Value)*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (sk LWESecretKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	lweDimension := len(sk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (sk LWESecretKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	return vecWriteTo(sk.Value, w)
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] LWEDimension
//	    Value
func (sk LWESecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = sk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = sk.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(sk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (sk *LWESecretKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

	*sk = NewLWESecretKeyCustom[T](lweDimension)

	return
}

// valueReadFrom reads the value.
func (sk *LWESecretKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	return vecReadFrom(sk.Value, r)
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (sk *LWESecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = sk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = sk.valueReadFrom(r); err != nil {
		return n + nRead, err
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
	glweRank := len(pk.Value)
	polyDegree := pk.Value[0].Value[0].Degree()
	return 16 + glweRank*(glweRank+1)*polyDegree*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (pk LWEPublicKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(pk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := pk.Value[0].Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (pk LWEPublicKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := pk.Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range pk.Value {
		for j := range pk.Value[i].Value {
			if nWrite, err = vecWriteToBuffered(pk.Value[i].Value[j].Coeffs, buf, w); err != nil {
				return n + nWrite, err
			}
			n += nWrite
		}
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
func (pk LWEPublicKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = pk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = pk.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(pk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (pk *LWEPublicKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*pk = NewLWEPublicKeyCustom[T](glweRank, polyDegree)

	return
}

// valueReadFrom reads the value.
func (pk *LWEPublicKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := pk.Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range pk.Value {
		for j := range pk.Value[i].Value {
			if nRead, err = vecReadFromBuffered(pk.Value[i].Value[j].Coeffs, buf, r); err != nil {
				return n + nRead, err
			}
			n += nRead
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pk *LWEPublicKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = pk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = pk.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

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
	return num.ByteSizeT[T]()
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	Value
func (pt LWEPlaintext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = vecWriteTo([]T{pt.Value}, w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(pt.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pt *LWEPlaintext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	buf := []T{0}
	if nRead, err = vecReadFrom(buf, r); err != nil {
		return n + nRead, err
	}
	n += nRead

	pt.Value = buf[0]

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

// ByteSize returns the size of the ciphertext in bytes.
func (ct LevCiphertext[T]) ByteSize() int {
	level := len(ct.Value)
	lweDimension := len(ct.Value[0].Value) - 1

	return 24 + level*(lweDimension+1)*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (ct LevCiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ct.GadgetParameters.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := len(ct.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	lweDimension := len(ct.Value[0].Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct LevCiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	lweDimension := len(ct.Value[0].Value) - 1
	buf := make([]byte, (lweDimension+1)*num.ByteSizeT[T]())

	for i := range ct.Value {
		if nWrite, err = vecWriteToBuffered(ct.Value[i].Value, buf, w); err != nil {
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
//	[8] Base
//	[8] Level
//	[8] LWEDimension
//	    Value
func (ct LevCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *LevCiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewLevCiphertextCustom(lweDimension, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *LevCiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	lweDimension := len(ct.Value[0].Value) - 1
	buf := make([]byte, (lweDimension+1)*num.ByteSizeT[T]())

	for i := range ct.Value {
		if nRead, err = vecReadFromBuffered(ct.Value[i].Value, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *LevCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

	return 24 + (lweDimension+1)*level*(lweDimension+1)*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (ct GSWCiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ct.GadgetParameters.base
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

	lweDimension := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct GSWCiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	lweDimension := len(ct.Value) - 1
	buf := make([]byte, (lweDimension+1)*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			if nWrite, err = vecWriteToBuffered(ct.Value[i].Value[j].Value, buf, w); err != nil {
				return n + nWrite, err
			}
			n += nWrite
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
//	[8] LWEDimension
//	    Value
func (ct GSWCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *GSWCiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewGSWCiphertextCustom(lweDimension, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *GSWCiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	lweDimension := len(ct.Value) - 1
	buf := make([]byte, (lweDimension+1)*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			if nRead, err = vecReadFromBuffered(ct.Value[i].Value[j].Value, buf, r); err != nil {
				return n + nRead, err
			}
			n += nRead
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GSWCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

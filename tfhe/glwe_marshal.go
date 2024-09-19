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

// headerWriteTo writes the header.
func (sk GLWESecretKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(sk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := sk.Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (sk GLWESecretKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := sk.Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range sk.Value {
		if nWrite, err = vecWriteToBuffered(sk.Value[i].Coeffs, buf, w); err != nil {
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
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (sk GLWESecretKey[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (sk *GLWESecretKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*sk = NewGLWESecretKeyCustom[T](glweRank, polyDegree)

	return
}

// valueReadFrom reads the value.
func (sk *GLWESecretKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := sk.Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range sk.Value {
		if nRead, err = vecReadFromBuffered(sk.Value[i].Coeffs, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (sk *GLWESecretKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = sk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = sk.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

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

// headerWriteTo writes the header.
func (pk GLWEPublicKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
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
func (pk GLWEPublicKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
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
func (pk GLWEPublicKey[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (pk *GLWEPublicKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*pk = NewGLWEPublicKeyCustom[T](glweRank, polyDegree)

	return
}

// valueReadFrom reads the value.
func (pk *GLWEPublicKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
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
func (pk *GLWEPublicKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

// headerWriteTo writes the header.
func (pt GLWEPlaintext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	polyDegree := pt.Value.Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (pt GLWEPlaintext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = vecWriteTo(pt.Value.Coeffs, w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	return
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] PolyDegree
//	    Value
func (pt GLWEPlaintext[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = pt.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = pt.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(pt.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (pt *GLWEPlaintext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*pt = NewGLWEPlaintextCustom[T](polyDegree)

	return
}

// valueReadFrom reads the value.
func (pt *GLWEPlaintext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	return vecReadFrom(pt.Value.Coeffs, r)
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (pt *GLWEPlaintext[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = pt.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = pt.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

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

// headerWriteTo writes the header.
func (ct GLWECiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	glweRank := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ct.Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct GLWECiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for _, p := range ct.Value {
		if nWrite, err = vecWriteToBuffered(p.Coeffs, buf, w); err != nil {
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
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct GLWECiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *GLWECiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*ct = NewGLWECiphertextCustom[T](glweRank, polyDegree)

	return
}

// valueReadFrom reads the value.
func (ct *GLWECiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for _, p := range ct.Value {
		if nRead, err = vecReadFromBuffered(p.Coeffs, buf, r); err != nil {
			return n + nRead, err
		}
		n += nRead
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GLWECiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

// headerWriteTo writes the header.
func (ct GLevCiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
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

	glweRank := len(ct.Value[0].Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ct.Value[0].Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct GLevCiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			if nWrite, err = vecWriteToBuffered(ct.Value[i].Value[j].Coeffs, buf, w); err != nil {
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
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct GLevCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *GLevCiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewGLevCiphertextCustom(glweRank, polyDegree, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *GLevCiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			if nRead, err = vecReadFromBuffered(ct.Value[i].Value[j].Coeffs, buf, r); err != nil {
				return n + nRead, err
			}
			n += nRead
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GLevCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

// headerWriteTo writes the header.
func (ct GGSWCiphertext[T]) headerWriteTo(w io.Writer) (n int64, err error) {
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

	glweRank := len(ct.Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ct GGSWCiphertext[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nWrite, err = vecWriteToBuffered(ct.Value[i].Value[j].Value[k].Coeffs, buf, w); err != nil {
					return n + nWrite, err
				}
				n += nWrite
			}
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
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (ct GGSWCiphertext[T]) WriteTo(w io.Writer) (n int64, err error) {
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
func (ct *GGSWCiphertext[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*ct = NewGGSWCiphertextCustom(glweRank, polyDegree, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ct *GGSWCiphertext[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ct.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*num.ByteSizeT[T]())

	for i := range ct.Value {
		for j := range ct.Value[i].Value {
			for k := range ct.Value[i].Value[j].Value {
				if nRead, err = vecReadFromBuffered(ct.Value[i].Value[j].Value[k].Coeffs, buf, r); err != nil {
					return n + nRead, err
				}
				n += nRead
			}
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ct *GGSWCiphertext[T]) ReadFrom(r io.Reader) (n int64, err error) {
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

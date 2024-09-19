package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the key in bytes.
func (ksk LWEKeySwitchKey[T]) ByteSize() int {
	inputDimension := len(ksk.Value)
	level := len(ksk.Value[0].Value)
	outputDimension := len(ksk.Value[0].Value[0].Value) - 1

	return 32 + inputDimension*level*(outputDimension+1)*num.ByteSizeT[T]()
}

// headerWriteTo writes the header.
func (ksk LWEKeySwitchKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ksk.GadgetParameters.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := ksk.GadgetParameters.level
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	inputDimension := len(ksk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(inputDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	outputDimension := len(ksk.Value[0].Value[0].Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(outputDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ksk LWEKeySwitchKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	outputDimension := len(ksk.Value[0].Value[0].Value) - 1
	buf := make([]byte, (outputDimension+1)*num.ByteSizeT[T]())

	for i := range ksk.Value {
		for j := range ksk.Value[i].Value {
			if nWrite, err = vecWriteToBuffered(ksk.Value[i].Value[j].Value, buf, w); err != nil {
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
//	[8] InputDimension
//	[8] OutputDimension
//	    Value
func (ksk LWEKeySwitchKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = ksk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = ksk.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(ksk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (ksk *LWEKeySwitchKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	inputDimension := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	outputDimension := int(binary.BigEndian.Uint64(buf[:]))

	*ksk = NewLWEKeySwitchKeyCustom(inputDimension, outputDimension, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ksk *LWEKeySwitchKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	outputDimension := len(ksk.Value[0].Value[0].Value) - 1
	buf := make([]byte, (outputDimension+1)*num.ByteSizeT[T]())

	for i := range ksk.Value {
		for j := range ksk.Value[i].Value {
			if nRead, err = vecReadFromBuffered(ksk.Value[i].Value[j].Value, buf, r); err != nil {
				return n + nRead, err
			}
			n += nRead
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ksk *LWEKeySwitchKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = ksk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = ksk.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (ksk LWEKeySwitchKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ksk.ByteSize()))
	_, err = ksk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (ksk *LWEKeySwitchKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := ksk.ReadFrom(buf)
	return err
}

// ByteSize returns the size of the key in bytes.
func (ksk GLWEKeySwitchKey[T]) ByteSize() int {
	inputRank := len(ksk.Value)
	level := len(ksk.Value[0].Value)
	outputRank := len(ksk.Value[0].Value[0].Value) - 1
	polyDegree := ksk.Value[0].Value[0].Value[0].Degree()

	return 40 + inputRank*level*(outputRank+1)*polyDegree*8
}

// headerWriteTo writes the header.
func (ksk GLWEKeySwitchKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := ksk.GadgetParameters.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := ksk.GadgetParameters.level
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	inputRank := len(ksk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(inputRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	outputRank := len(ksk.Value[0].Value[0].Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(outputRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := ksk.Value[0].Value[0].Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (ksk GLWEKeySwitchKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := ksk.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range ksk.Value {
		for j := range ksk.Value[i].Value {
			for k := range ksk.Value[i].Value[j].Value {
				if nWrite, err = floatVecWriteToBuffered(ksk.Value[i].Value[j].Value[k].Coeffs, buf, w); err != nil {
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
//	[8] InputRank
//	[8] OutputRank
//	[8] PolyDegree
//	    Value
func (ksk GLWEKeySwitchKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = ksk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = ksk.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(ksk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (ksk *GLWEKeySwitchKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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
	inputRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	outputRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	*ksk = NewGLWEKeySwitchKeyCustom(inputRank, outputRank, polyDegree, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (ksk *GLWEKeySwitchKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := ksk.Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range ksk.Value {
		for j := range ksk.Value[i].Value {
			for k := range ksk.Value[i].Value[j].Value {
				if nRead, err = floatVecReadFromBuffered(ksk.Value[i].Value[j].Value[k].Coeffs, buf, r); err != nil {
					return n + nRead, err
				}
				n += nRead
			}
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (ksk *GLWEKeySwitchKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = ksk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = ksk.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

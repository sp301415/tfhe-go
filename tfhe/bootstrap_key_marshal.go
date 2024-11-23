package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
)

// ByteSize returns the size of the key in bytes.
func (evk EvaluationKey[T]) ByteSize() int {
	if len(evk.KeySwitchKey.Value) > 0 {
		return 1 + evk.BlindRotateKey.ByteSize() + evk.KeySwitchKey.ByteSize()
	} else {
		return 1 + evk.BlindRotateKey.ByteSize() + evk.KeySwitchKey.GadgetParameters.ByteSize()
	}
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	 [1] IsKeySwitchKeyPresent
//		 BlindRotateKey
//		 KeySwitchKey
//
// If IsKeySwitchKeyPresent is 0, then only the GadgetParameters of the KeySwitchKey is written.
func (evk EvaluationKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var nWrite64 int64

	var isKeySwitchKeyPresent byte
	if len(evk.KeySwitchKey.Value) > 0 {
		isKeySwitchKeyPresent = 1
	}

	if nWrite, err = w.Write([]byte{isKeySwitchKeyPresent}); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if nWrite64, err = evk.BlindRotateKey.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if isKeySwitchKeyPresent == 0 {
		if nWrite64, err = evk.KeySwitchKey.GadgetParameters.WriteTo(w); err != nil {
			return n + nWrite64, err
		}
		n += nWrite64
	} else {
		if nWrite64, err = evk.KeySwitchKey.WriteTo(w); err != nil {
			return n + nWrite64, err
		}
		n += nWrite64
	}

	if n < int64(evk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (evk *EvaluationKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var nRead64 int64

	var buf [1]byte
	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	isKeySwitchKeyPresent := buf[0]

	if nRead64, err = evk.BlindRotateKey.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	if isKeySwitchKeyPresent == 0 {
		var keySwitchParams GadgetParameters[T]
		if nRead64, err = keySwitchParams.ReadFrom(r); err != nil {
			return n + nRead64, err
		}
		n += nRead64

		evk.KeySwitchKey = NewLWEKeySwitchKeyCustom(0, 0, keySwitchParams)
	} else {
		if nRead64, err = evk.KeySwitchKey.ReadFrom(r); err != nil {
			return n + nRead64, err
		}
		n += nRead64
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

// ByteSize returns the size of the key in bytes.
func (brk BlindRotateKey[T]) ByteSize() int {
	lweDimension := len(brk.Value)
	glweRank := len(brk.Value[0].Value) - 1
	level := len(brk.Value[0].Value[0].Value)
	polyDegree := brk.Value[0].Value[0].Value[0].Value[0].Degree()

	return 40 + lweDimension*(glweRank+1)*level*(glweRank+1)*polyDegree*8
}

// headerWriteTo writes the header.
func (brk BlindRotateKey[T]) headerWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := brk.GadgetParameters.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := brk.GadgetParameters.level
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	lweDimension := len(brk.Value)
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	glweRank := len(brk.Value[0].Value) - 1
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := brk.Value[0].Value[0].Value[0].Value[0].Degree()
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	return
}

// valueWriteTo writes the value.
func (brk BlindRotateKey[T]) valueWriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	polyDegree := brk.Value[0].Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range brk.Value {
		for j := range brk.Value[i].Value {
			for k := range brk.Value[i].Value[j].Value {
				for l := range brk.Value[i].Value[j].Value[k].Value {
					if nWrite, err = floatVecWriteToBuffered(brk.Value[i].Value[j].Value[k].Value[l].Coeffs, buf, w); err != nil {
						return n + nWrite, err
					}
					n += nWrite
				}
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
//	[8] LWEDimension
//	[8] GLWERank
//	[8] PolyDegree
//	    Value
func (brk BlindRotateKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int64

	if nWrite, err = brk.headerWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if nWrite, err = brk.valueWriteTo(w); err != nil {
		return n + nWrite, err
	}
	n += nWrite

	if n < int64(brk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// headerReadFrom reads the header, and initializes the value.
func (brk *BlindRotateKey[T]) headerReadFrom(r io.Reader) (n int64, err error) {
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

	*brk = NewBlindRotateKeyCustom(lweDimension, glweRank, polyDegree, GadgetParametersLiteral[T]{Base: base, Level: level}.Compile())

	return
}

// valueReadFrom reads the value.
func (brk *BlindRotateKey[T]) valueReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	polyDegree := brk.Value[0].Value[0].Value[0].Value[0].Degree()
	buf := make([]byte, polyDegree*8)

	for i := range brk.Value {
		for j := range brk.Value[i].Value {
			for k := range brk.Value[i].Value[j].Value {
				for l := range brk.Value[i].Value[j].Value[k].Value {
					if nRead, err = floatVecReadFromBuffered(brk.Value[i].Value[j].Value[k].Value[l].Coeffs, buf, r); err != nil {
						return n + nRead, err
					}
					n += nRead
				}
			}
		}
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (brk *BlindRotateKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int64

	if nRead, err = brk.headerReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	if nRead, err = brk.valueReadFrom(r); err != nil {
		return n + nRead, err
	}
	n += nRead

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (brk BlindRotateKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, brk.ByteSize()))
	_, err = brk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (brk *BlindRotateKey[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := brk.ReadFrom(buf)
	return err
}

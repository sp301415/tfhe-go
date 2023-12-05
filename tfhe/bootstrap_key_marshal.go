package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/sp301415/tfhe-go/math/num"
)

// ByteSize returns the size of the key in bytes.
func (evk EvaluationKey[T]) ByteSize() int {
	return evk.BootstrapKey.ByteSize() + evk.KeySwitchKey.ByteSize()
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	BootstrapKey | KeySwitchKey
func (evk EvaluationKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int64

	nn, err = evk.BootstrapKey.WriteTo(w)
	n += nn
	if err != nil {
		return
	}

	nn, err = evk.KeySwitchKey.WriteTo(w)
	n += nn
	if err != nil {
		return
	}

	if n < int64(evk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (evk *EvaluationKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int64

	nn, err = evk.BootstrapKey.ReadFrom(r)
	n += nn
	if err != nil {
		return
	}

	nn, err = evk.KeySwitchKey.ReadFrom(r)
	n += nn
	if err != nil {
		return
	}

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (evk EvaluationKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, evk.ByteSize()))
	_, err = evk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (evk *EvaluationKey[T]) UnmarshalBinary(data []byte) error {
	_, err := evk.ReadFrom(bytes.NewReader(data))
	return err
}

// ByteSize returns the size of the key in bytes.
func (bsk BootstrapKey[T]) ByteSize() int {
	lweDimension := len(bsk.Value)
	glweDimension := len(bsk.Value[0].Value) - 1
	level := len(bsk.Value[0].Value[0].Value)
	polyDegree := bsk.Value[0].Value[0].Value[0].Value[0].Degree()

	return 16 + 24 + lweDimension*(glweDimension+1)*level*(glweDimension+1)*polyDegree*8
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	   8       8                   8               8            8
//	Base | Level | LWESmallDimension | GLWEDimension | PolyDegree | Value
func (bsk BootstrapKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	lweSmallDimension := len(bsk.Value)
	glweDimension := len(bsk.Value[0].Value) - 1
	level := len(bsk.Value[0].Value[0].Value)
	polyDegree := bsk.Value[0].Value[0].Value[0].Value[0].Degree()

	var metadta [40]byte
	binary.BigEndian.PutUint64(metadta[0:8], uint64(bsk.GadgetParameters.base))
	binary.BigEndian.PutUint64(metadta[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadta[16:24], uint64(lweSmallDimension))
	binary.BigEndian.PutUint64(metadta[24:32], uint64(glweDimension))
	binary.BigEndian.PutUint64(metadta[32:40], uint64(polyDegree))
	nn, err = w.Write(metadta[:])
	n += int64(nn)
	if err != nil {
		return
	}

	buf := make([]byte, polyDegree*8)

	for _, fggsw := range bsk.Value {
		for _, fglev := range fggsw.Value {
			for _, fglwe := range fglev.Value {
				for _, fp := range fglwe.Value {
					var b int
					for i := range fp.Coeffs {
						binary.BigEndian.PutUint64(buf[(b+0)*8:(b+1)*8], math.Float64bits(real(fp.Coeffs[i])))
						binary.BigEndian.PutUint64(buf[(b+1)*8:(b+2)*8], math.Float64bits(imag(fp.Coeffs[i])))
						b += 2
					}

					nn, err = w.Write(buf[:polyDegree*8])
					n += int64(nn)
					if err != nil {
						return
					}
				}
			}
		}
	}

	if n < int64(bsk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (bsk *BootstrapKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [40]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	lweSmallDimension := int(binary.BigEndian.Uint64(metadata[16:24]))
	glweDimension := int(binary.BigEndian.Uint64(metadata[24:32]))
	polyDegree := int(binary.BigEndian.Uint64(metadata[32:40]))

	*bsk = NewBootstrapKeyCustom[T](lweSmallDimension, glweDimension, polyDegree, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	buf := make([]byte, polyDegree*8)

	for _, fggsw := range bsk.Value {
		for _, fglev := range fggsw.Value {
			for _, fglwe := range fglev.Value {
				for _, fp := range fglwe.Value {
					nn, err = io.ReadFull(r, buf)
					n += int64(nn)
					if err != nil {
						return
					}

					var b int
					for i := range fp.Coeffs {
						fp.Coeffs[i] = complex(
							math.Float64frombits(binary.BigEndian.Uint64(buf[(b+0)*8:(b+1)*8])),
							math.Float64frombits(binary.BigEndian.Uint64(buf[(b+1)*8:(b+2)*8])))
						b += 2
					}
				}
			}
		}
	}

	return
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (bsk BootstrapKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, bsk.ByteSize()))
	_, err = bsk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (bsk *BootstrapKey[T]) UnmarshalBinary(data []byte) error {
	_, err := bsk.ReadFrom(bytes.NewReader(data))
	return err
}

// ByteSize returns the size of the key in bytes.
func (ksk KeySwitchKey[T]) ByteSize() int {
	inputDimension := len(ksk.Value)
	level := len(ksk.Value[0].Value)
	outputDimension := len(ksk.Value[0].Value[0].Value) - 1

	return 16 + 16 + inputDimension*level*(outputDimension+1)*(num.SizeT[T]()/8)
}

// WriteTo implements the io.WriterTo interface.
//
// The encoded form is as follows:
//
//	   8       8                   8                    8
//	Base | Level | InputLWEDimension | OutputLWEDimension | Value
func (ksk KeySwitchKey[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nn int

	inputDimension := len(ksk.Value)
	level := len(ksk.Value[0].Value)
	outputDimension := len(ksk.Value[0].Value[0].Value) - 1

	var metadta [32]byte
	binary.BigEndian.PutUint64(metadta[0:8], uint64(ksk.GadgetParameters.base))
	binary.BigEndian.PutUint64(metadta[8:16], uint64(level))
	binary.BigEndian.PutUint64(metadta[16:24], uint64(inputDimension))
	binary.BigEndian.PutUint64(metadta[24:32], uint64(outputDimension))
	nn, err = w.Write(metadta[:])
	n += int64(nn)
	if err != nil {
		return
	}

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (outputDimension+1)*4)

		for _, lev := range ksk.Value {
			for _, lwe := range lev.Value {
				for i := range lwe.Value {
					binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], uint32(lwe.Value[i]))
				}

				nn, err = w.Write(buf[:])
				n += int64(nn)
				if err != nil {
					return
				}
			}
		}

	case uint64:
		buf := make([]byte, (outputDimension+1)*8)

		for _, lev := range ksk.Value {
			for _, lwe := range lev.Value {
				for i := range lwe.Value {
					binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], uint64(lwe.Value[i]))
				}

				nn, err = w.Write(buf[:])
				n += int64(nn)
				if err != nil {
					return
				}
			}
		}
	}

	if n < int64(ksk.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (ksk *KeySwitchKey[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nn int

	var metadata [32]byte
	nn, err = io.ReadFull(r, metadata[:])
	n += int64(nn)
	if err != nil {
		return
	}

	base := int(binary.BigEndian.Uint64(metadata[0:8]))
	level := int(binary.BigEndian.Uint64(metadata[8:16]))
	inputDimension := int(binary.BigEndian.Uint64(metadata[16:24]))
	outputDimension := int(binary.BigEndian.Uint64(metadata[24:32]))

	*ksk = NewKeySwitchKey[T](inputDimension, outputDimension, GadgetParametersLiteral[T]{Base: T(base), Level: int(level)}.Compile())

	var z T
	switch any(z).(type) {
	case uint32:
		buf := make([]byte, (outputDimension+1)*4)

		for _, lev := range ksk.Value {
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
		buf := make([]byte, (outputDimension+1)*8)

		for _, lev := range ksk.Value {
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

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (ksk KeySwitchKey[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, ksk.ByteSize()))
	_, err = ksk.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (ksk *KeySwitchKey[T]) UnmarshalBinary(data []byte) error {
	_, err := ksk.ReadFrom(bytes.NewReader(data))
	return err
}
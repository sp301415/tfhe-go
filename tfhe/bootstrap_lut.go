package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// LookUpTable is a polynomial that is the lookup table
// for function evaluations during programmable bootstrapping.
type LookUpTable[T TorusInt] struct {
	// Value has length lutExtendFactor.
	Value []poly.Poly[T]
}

// NewLUT creates a new lookup table.
func NewLUT[T TorusInt](params Parameters[T]) LookUpTable[T] {
	lut := make([]poly.Poly[T], params.lutExtendFactor)
	for i := 0; i < params.lutExtendFactor; i++ {
		lut[i] = poly.NewPoly[T](params.polyRank)
	}

	return LookUpTable[T]{Value: lut}
}

// NewLUTCustom creates a new lookup table with custom size.
func NewLUTCustom[T TorusInt](extendFactor, polyRank int) LookUpTable[T] {
	lut := make([]poly.Poly[T], extendFactor)
	for i := 0; i < extendFactor; i++ {
		lut[i] = poly.NewPoly[T](polyRank)
	}

	return LookUpTable[T]{Value: lut}
}

// Copy returns a copy of the LUT.
func (lut LookUpTable[T]) Copy() LookUpTable[T] {
	lutCopy := make([]poly.Poly[T], len(lut.Value))
	for i := 0; i < len(lut.Value); i++ {
		lutCopy[i] = lut.Value[i].Copy()
	}
	return LookUpTable[T]{Value: lutCopy}
}

// CopyFrom copies values from the LUT.
func (lut *LookUpTable[T]) CopyFrom(lutIn LookUpTable[T]) {
	for i := 0; i < len(lut.Value); i++ {
		lut.Value[i].CopyFrom(lutIn.Value[i])
	}
}

// Clear clears the LUT.
func (lut *LookUpTable[T]) Clear() {
	for i := 0; i < len(lut.Value); i++ {
		lut.Value[i].Clear()
	}
}

// GenLUT generates a lookup table based on function f.
// Input and output of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLUT(f func(int) int) LookUpTable[T] {
	lutOut := NewLUT(e.Params)
	e.GenLUTTo(lutOut, f)
	return lutOut
}

// GenLUTTo generates a lookup table based on function f and writes it to lutOut.
// Input and output of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLUTTo(lutOut LookUpTable[T], f func(int) int) {
	e.GenLUTCustomTo(lutOut, f, e.Params.messageModulus, e.Params.scale)
}

// GenLUTFull generates a lookup table based on function f.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLUTFull(f func(int) T) LookUpTable[T] {
	lutOut := NewLUT(e.Params)
	e.GenLUTFullTo(lutOut, f)
	return lutOut
}

// GenLUTFullTo generates a lookup table based on function f and writes it to lutOut.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLUTFullTo(lutOut LookUpTable[T], f func(int) T) {
	e.GenLUTCustomFullTo(lutOut, f, e.Params.messageModulus)
}

// GenLUTCustom generates a lookup table based on function f using custom messageModulus and scale.
// Input and output of f is cut by messageModulus.
func (e *Evaluator[T]) GenLUTCustom(f func(int) int, messageModulus, scale T) LookUpTable[T] {
	lutOut := NewLUT(e.Params)
	e.GenLUTCustomTo(lutOut, f, messageModulus, scale)
	return lutOut
}

// GenLUTCustomTo generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Input and output of f is cut by messageModulus.
func (e *Evaluator[T]) GenLUTCustomTo(lutOut LookUpTable[T], f func(int) int, messageModulus, scale T) {
	e.GenLUTCustomFullTo(lutOut, func(x int) T { return e.EncodeLWECustom(f(x), messageModulus, scale).Value }, messageModulus)
}

// GenLUTCustomFull generates a lookup table based on function f using custom messageModulus and scale.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLUTCustomFull(f func(int) T, messageModulus T) LookUpTable[T] {
	lutOut := NewLUT(e.Params)
	e.GenLUTCustomFullTo(lutOut, f, messageModulus)
	return lutOut
}

// GenLUTCustomFullTo generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLUTCustomFullTo(lutOut LookUpTable[T], f func(int) T, messageModulus T) {
	for x := 0; x < int(messageModulus); x++ {
		start := num.DivRound(x*e.Params.lutSize, int(messageModulus))
		end := num.DivRound((x+1)*e.Params.lutSize, int(messageModulus))
		y := f(x)
		for xx := start; xx < end; xx++ {
			e.buf.lutRaw[xx] = y
		}
	}

	offset := num.DivRound(e.Params.lutSize, int(2*messageModulus))
	vec.RotateInPlace(e.buf.lutRaw, -offset)
	for i := e.Params.lutSize - offset; i < e.Params.lutSize; i++ {
		e.buf.lutRaw[i] = -e.buf.lutRaw[i]
	}

	for i := 0; i < e.Params.lutExtendFactor; i++ {
		for j := 0; j < e.Params.polyRank; j++ {
			lutOut.Value[i].Coeffs[j] = e.buf.lutRaw[j*e.Params.lutExtendFactor+i]
		}
	}
}

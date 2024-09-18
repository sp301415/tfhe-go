package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// LookUpTable is a polynomial that is the lookup table
// for function evaluations during programmable bootstrapping.
type LookUpTable[T TorusInt] struct {
	Value []T
}

// NewLookUpTable allocates an empty lookup table.
func NewLookUpTable[T TorusInt](params Parameters[T]) LookUpTable[T] {
	return LookUpTable[T]{Value: make([]T, params.lookUpTableSize)}
}

// Copy returns a copy of the LUT.
func (lut LookUpTable[T]) Copy() LookUpTable[T] {
	return LookUpTable[T]{Value: vec.Copy(lut.Value)}
}

// CopyFrom copies values from the LUT.
func (lut *LookUpTable[T]) CopyFrom(lutIn LookUpTable[T]) {
	vec.CopyAssign(lutIn.Value, lut.Value)
}

// Clear clears the LUT.
func (lut *LookUpTable[T]) Clear() {
	vec.Fill(lut.Value, 0)
}

// GenLookUpTable generates a lookup table based on function f.
// Input and output of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLookUpTable(f func(int) int) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableAssign generates a lookup table based on function f and writes it to lutOut.
// Input and output of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLookUpTableAssign(f func(int) int, lutOut LookUpTable[T]) {
	e.GenLookUpTableCustomAssign(f, e.Parameters.messageModulus, e.Parameters.scale, lutOut)
}

// GenLookUpTableFull generates a lookup table based on function f.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLookUpTableFull(f func(int) T) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableFullAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableFullAssign generates a lookup table based on function f and writes it to lutOut.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLookUpTableFullAssign(f func(int) T, lutOut LookUpTable[T]) {
	e.GenLookUpTableFullCustomAssign(f, e.Parameters.messageModulus, e.Parameters.scale, lutOut)
}

// GenLookUpTableCustom generates a lookup table based on function f using custom messageModulus and scale.
// Input and output of f is cut by messageModulus.
func (e *Evaluator[T]) GenLookUpTableCustom(f func(int) int, messageModulus, scale T) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableCustomAssign(f, messageModulus, scale, lutOut)
	return lutOut
}

// GenLookUpTableCustomAssign generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Input and output of f is cut by messageModulus.
func (e *Evaluator[T]) GenLookUpTableCustomAssign(f func(int) int, messageModulus, scale T, lutOut LookUpTable[T]) {
	for x := 0; x < int(messageModulus); x++ {
		start := num.DivRound(x*e.Parameters.lookUpTableSize, int(messageModulus))
		end := num.DivRound((x+1)*e.Parameters.lookUpTableSize, int(messageModulus))
		y := e.EncodeLWECustom(f(x), messageModulus, scale).Value
		for xx := start; xx < end; xx++ {
			lutOut.Value[xx] = y
		}
	}

	offset := num.DivRound(e.Parameters.lookUpTableSize, int(2*messageModulus))
	vec.RotateInPlace(lutOut.Value, -offset)
	for i := e.Parameters.lookUpTableSize - offset; i < e.Parameters.lookUpTableSize; i++ {
		lutOut.Value[i] = -lutOut.Value[i]
	}
}

// GenLookUpTableFullCustom generates a lookup table based on function f using custom messageModulus and scale.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLookUpTableFullCustom(f func(int) T, messageModulus, scale T) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableFullAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableFullCustomAssign generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLookUpTableFullCustomAssign(f func(int) T, messageModulus, scale T, lutOut LookUpTable[T]) {
	for x := 0; x < int(messageModulus); x++ {
		start := num.DivRound(x*e.Parameters.lookUpTableSize, int(messageModulus))
		end := num.DivRound((x+1)*e.Parameters.lookUpTableSize, int(messageModulus))
		y := f(x)
		for xx := start; xx < end; xx++ {
			lutOut.Value[xx] = y
		}
	}

	offset := num.DivRound(e.Parameters.lookUpTableSize, int(2*messageModulus))
	vec.RotateInPlace(lutOut.Value, -offset)
	for i := e.Parameters.lookUpTableSize - offset; i < e.Parameters.lookUpTableSize; i++ {
		lutOut.Value[i] = -lutOut.Value[i]
	}
}

package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BinaryEvaluator is a multi-key variant of [tfhe.BinaryEvaluator].
type BinaryEvaluator[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEvaluator.
	*tfhe.BinaryEncoder[T]
	// Parameters holds the parameters for this BinaryEvaluator.
	Parameters Parameters[T]
	// BaseEvaluator is a generic Evalutor for this BinaryEvaluator.
	BaseEvaluator *Evaluator[T]
	// signLUT holds a LUT for sign function.
	signLUT tfhe.LookUpTable[T]
}

// NewBinaryEvaluator allocates an empty BinaryEvaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewBinaryEvaluator[T tfhe.TorusInt](params Parameters[T], evk map[int]EvaluationKey[T]) *BinaryEvaluator[T] {
	signLUT := tfhe.NewLookUpTable(params.Parameters)
	vec.Fill(signLUT.Value, 1<<(params.LogQ()-3))

	return &BinaryEvaluator[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.Parameters),
		Parameters:    params,
		BaseEvaluator: NewEvaluator(params, evk),
		signLUT:       signLUT,
	}
}

// ShallowCopy returns a shallow copy of this BinaryEvaluator.
// Returned BinaryEvaluator is safe for concurrent use.
func (e *BinaryEvaluator[T]) ShallowCopy() *BinaryEvaluator[T] {
	return &BinaryEvaluator[T]{
		BinaryEncoder: e.BinaryEncoder,
		Parameters:    e.Parameters,
		BaseEvaluator: e.BaseEvaluator.ShallowCopy(),
		signLUT:       e.signLUT,
	}
}

// NOT returns NOT ct0.
// Equivalent to ^ct0.
func (e *BinaryEvaluator[T]) NOT(ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NOTAssign(ct0, ctOut)
	return ctOut
}

// NOTAssign computes ctOut = NOT ct0.
// Equivalent to ^ct0.
func (e *BinaryEvaluator[T]) NOTAssign(ct0, ctOut LWECiphertext[T]) {
	// ctOut = -ct0
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i]
	}
}

// AND returns ct0 AND ct1.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) AND(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ANDAssign(ct0, ct1, ctOut)
	return ctOut
}

// ANDAssign computes ctOut = ct0 AND ct1.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) ANDAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// ANDParallel returns ct0 AND ct1 in parallel.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) ANDParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ANDParallelAssign(ct0, ct1, ctOut)
	return ctOut
}

// ANDParallelAssign computes ctOut = ct0 AND ct1 in parallel.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) ANDParallelAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTParallelAssign(ctOut, e.signLUT, ctOut)
}

// NAND returns ct0 NAND ct1.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NAND(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NANDAssign(ct0, ct1, ctOut)
	return ctOut
}

// NANDAssign computes ctOut = ct0 NAND ct1.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NANDAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// NANDParallel returns ct0 NAND ct1 in parallel.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NANDParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NANDParallelAssign(ct0, ct1, ctOut)
	return ctOut
}

// NANDParallelAssign computes ctOut = ct0 NAND ct1 in parallel.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NANDParallelAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTParallelAssign(ctOut, e.signLUT, ctOut)
}

// OR returns ct0 OR ct1.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) OR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ORAssign(ct0, ct1, ctOut)
	return ctOut
}

// ORAssign computes ctOut = ct0 OR ct1.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) ORAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// ORParallel returns ct0 OR ct1 in parallel.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) ORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ORParallelAssign(ct0, ct1, ctOut)
	return ctOut
}

// ORParallelAssign computes ctOut = ct0 OR ct1 in parallel.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) ORParallelAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTParallelAssign(ctOut, e.signLUT, ctOut)
}

// NOR returns ct0 NOR ct1.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NOR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NORAssign(ct0, ct1, ctOut)
	return ctOut
}

// NORAssign computes ctOut = ct0 NOR ct1.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NORAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// NORParallel returns ct0 NOR ct1 in parallel.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NORParallelAssign(ct0, ct1, ctOut)
	return ctOut
}

// NORParallelAssign computes ctOut = ct0 NOR ct1 in parallel.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NORParallelAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTParallelAssign(ctOut, e.signLUT, ctOut)
}

// XOR returns ct0 XOR ct1.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XOR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.XORAssign(ct0, ct1, ctOut)
	return ctOut
}

// XORAssign computes ctOut = ct0 XOR ct1.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XORAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// XORParallel returns ct0 XOR ct1 in parallel.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.XORParallelAssign(ct0, ct1, ctOut)
	return ctOut
}

// XORParallelAssign computes ctOut = ct0 XOR ct1 in parallel.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XORParallelAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTParallelAssign(ctOut, e.signLUT, ctOut)
}

// XNOR returns ct0 XNOR ct1.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNOR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.XNORAssign(ct0, ct1, ctOut)
	return ctOut
}

// XNORAssign computes ctOut = ct0 XNOR ct1.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNORAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (-ct0.Value[i] - ct1.Value[i])
	}
	ctOut.Value[0] -= 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// XNORParallel returns ct0 XNOR ct1 in parallel.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.XNORParallelAssign(ct0, ct1, ctOut)
	return ctOut
}

// XNORParallelAssign computes ctOut = ct0 XNOR ct1 in parallel.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNORParallelAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (-ct0.Value[i] - ct1.Value[i])
	}
	ctOut.Value[0] -= 1 << (e.Parameters.LogQ() - 3)

	e.BaseEvaluator.BootstrapLUTParallelAssign(ctOut, e.signLUT, ctOut)
}

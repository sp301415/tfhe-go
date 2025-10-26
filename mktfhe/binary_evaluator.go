package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BinaryEvaluator is a multi-key variant of [tfhe.BinaryEvaluator].
type BinaryEvaluator[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEvaluator.
	*tfhe.BinaryEncoder[T]
	// Params is the parameters for this BinaryEvaluator.
	Params Parameters[T]
	// Evaluator is a generic Evalutor for this BinaryEvaluator.
	Evaluator *Evaluator[T]
	// signLUT is a LUT for sign function.
	signLUT tfhe.LookUpTable[T]
}

// NewBinaryEvaluator creates a new BinaryEvaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewBinaryEvaluator[T tfhe.TorusInt](params Parameters[T], evk map[int]EvaluationKey[T]) *BinaryEvaluator[T] {
	signLUT := tfhe.NewLUT(params.subParams)
	vec.Fill(signLUT.Value[0].Coeffs, 1<<(params.LogQ()-3))

	return &BinaryEvaluator[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.subParams),
		Params:        params,
		Evaluator:     NewEvaluator(params, evk),
		signLUT:       signLUT,
	}
}

// ShallowCopy returns a shallow copy of this BinaryEvaluator.
// Returned BinaryEvaluator is safe for concurrent use.
func (e *BinaryEvaluator[T]) ShallowCopy() *BinaryEvaluator[T] {
	return &BinaryEvaluator[T]{
		BinaryEncoder: e.BinaryEncoder,
		Params:        e.Params,
		Evaluator:     e.Evaluator.ShallowCopy(),
		signLUT:       e.signLUT,
	}
}

// NOT returns NOT ct.
// Equivalent to ^ct.
func (e *BinaryEvaluator[T]) NOT(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NOTTo(ctOut, ct)
	return ctOut
}

// NOTTo computes ctOut = NOT ct0.
// Equivalent to ^ct0.
func (e *BinaryEvaluator[T]) NOTTo(ctOut, ct LWECiphertext[T]) {
	// ctOut = -ct
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct.Value[i]
	}
}

// AND returns ct0 AND ct1.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) AND(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ANDTo(ctOut, ct0, ct1)
	return ctOut
}

// ANDTo computes ctOut = ct0 AND ct1.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) ANDTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

// ANDParallel returns ct0 AND ct1 in parallel.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) ANDParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ANDParallelTo(ctOut, ct0, ct1)
	return ctOut
}

// ANDParallelTo computes ctOut = ct0 AND ct1 in parallel.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator[T]) ANDParallelTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTParallelTo(ctOut, ctOut, e.signLUT)
}

// NAND returns ct0 NAND ct1.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NAND(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NANDTo(ctOut, ct0, ct1)
	return ctOut
}

// NANDTo computes ctOut = ct0 NAND ct1.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NANDTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

// NANDParallel returns ct0 NAND ct1 in parallel.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NANDParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NANDParallelTo(ctOut, ct0, ct1)
	return ctOut
}

// NANDParallelTo computes ctOut = ct0 NAND ct1 in parallel.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator[T]) NANDParallelTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTParallelTo(ctOut, ctOut, e.signLUT)
}

// OR returns ct0 OR ct1.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) OR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ORTo(ctOut, ct0, ct1)
	return ctOut
}

// ORTo computes ctOut = ct0 OR ct1.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) ORTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

// ORParallel returns ct0 OR ct1 in parallel.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) ORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ORParallelTo(ctOut, ct0, ct1)
	return ctOut
}

// ORParallelTo computes ctOut = ct0 OR ct1 in parallel.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator[T]) ORParallelTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTParallelTo(ctOut, ctOut, e.signLUT)
}

// NOR returns ct0 NOR ct1.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NOR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NORTo(ctOut, ct0, ct1)
	return ctOut
}

// NORTo computes ctOut = ct0 NOR ct1.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NORTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

// NORParallel returns ct0 NOR ct1 in parallel.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NORParallelTo(ctOut, ct0, ct1)
	return ctOut
}

// NORParallelTo computes ctOut = ct0 NOR ct1 in parallel.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator[T]) NORParallelTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTParallelTo(ctOut, ctOut, e.signLUT)
}

// XOR returns ct0 XOR ct1.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XOR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.XORTo(ctOut, ct0, ct1)
	return ctOut
}

// XORTo computes ctOut = ct0 XOR ct1.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XORTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

// XORParallel returns ct0 XOR ct1 in parallel.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.XORParallelTo(ctOut, ct0, ct1)
	return ctOut
}

// XORParallelTo computes ctOut = ct0 XOR ct1 in parallel.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator[T]) XORParallelTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTParallelTo(ctOut, ctOut, e.signLUT)
}

// XNOR returns ct0 XNOR ct1.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNOR(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.XNORTo(ctOut, ct0, ct1)
	return ctOut
}

// XNORTo computes ctOut = ct0 XNOR ct1.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNORTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (-ct0.Value[i] - ct1.Value[i])
	}
	ctOut.Value[0] -= 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

// XNORParallel returns ct0 XNOR ct1 in parallel.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNORParallel(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.XNORParallelTo(ctOut, ct0, ct1)
	return ctOut
}

// XNORParallelTo computes ctOut = ct0 XNOR ct1 in parallel.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator[T]) XNORParallelTo(ctOut, ct0, ct1 LWECiphertext[T]) {
	for i := 0; i < e.Params.DefaultLWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (-ct0.Value[i] - ct1.Value[i])
	}
	ctOut.Value[0] -= 1 << (e.Params.LogQ() - 3)

	e.Evaluator.BootstrapLUTParallelTo(ctOut, ctOut, e.signLUT)
}

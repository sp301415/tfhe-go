package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// BinaryEvaluator evaluates homomorphic binary gates on ciphertexts.
// All LWE ciphertexts should be encrypted with [BinaryEncryptor].
// This is meant to be public, usually for servers.
//
// BinaryEvaluator is not safe for concurrent use.
// Use [*BinaryEvaluator.ShallowCopy] to get a safe copy.
type BinaryEvaluator[T TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEvaluator.
	*BinaryEncoder[T]
	// Params is the parameters for this BinaryEvaluator.
	Params Parameters[T]
	// Evaluator is a generic Evaluator for this BinaryEvaluator.
	Evaluator *Evaluator[T]
	// signLUT is a LUT for sign function.
	signLUT LookUpTable[T]
}

// NewBinaryEvaluator creates a new BinaryEvaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewBinaryEvaluator[T TorusInt](params Parameters[T], evk EvaluationKey[T]) *BinaryEvaluator[T] {
	signLUT := NewLUT(params)
	for i := 0; i < params.lutExtendFactor; i++ {
		vec.Fill(signLUT.Value[i].Coeffs, 1<<(params.logQ-3))
	}

	return &BinaryEvaluator[T]{
		BinaryEncoder: NewBinaryEncoder(params),
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
	// ctOut = -ct0
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
	ctOut.Value[0] -= 1 << (e.Params.logQ - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
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
	ctOut.Value[0] += 1 << (e.Params.logQ - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
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
	ctOut.Value[0] += 1 << (e.Params.logQ - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
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
	ctOut.Value[0] -= 1 << (e.Params.logQ - 3)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
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
	ctOut.Value[0] += 1 << (e.Params.logQ - 2)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
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
	ctOut.Value[0] -= 1 << (e.Params.logQ - 2)

	e.Evaluator.BootstrapLUTTo(ctOut, ctOut, e.signLUT)
}

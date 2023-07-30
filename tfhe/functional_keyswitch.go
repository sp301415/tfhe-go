package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// PrivataeFunctionalLWEKeySwitch applies LWE private functional keyswitching on ctIn and returns the result.
func (e Evaluator[T]) PrivateFunctionalLWEKeySwitch(ctIn []LWECiphertext[T], pfksk PrivateFunctionalLWEKeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.PrivateFunctionalLWEKeySwitchAssign(ctIn, pfksk, ctOut)
	return ctOut
}

// PrivateFunctionalLWEKeySwitchAssign applies LWE private functional keyswitching on ctIn and writes it to ctOut.
func (e Evaluator[T]) PrivateFunctionalLWEKeySwitchAssign(ctIn []LWECiphertext[T], pfksk PrivateFunctionalLWEKeySwitchKey[T], ctOut LWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(pfksk.decompParams)
	for i := 0; i < pfksk.InputCount(); i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			e.DecomposeAssign(ctIn[i].Value[j], buffDecomposed, pfksk.decompParams)
			for k := 0; k < pfksk.decompParams.level; k++ {
				if i == 0 && j == 0 && k == 0 {
					e.ScalarMulLWEAssign(pfksk.Value[i].Value[j].Value[k], -buffDecomposed[k], ctOut)
				} else {
					e.ScalarMulSubLWEAssign(pfksk.Value[i].Value[j].Value[k], buffDecomposed[k], ctOut)
				}
			}
		}
	}
}

// PrivateFunctionalGLWEKeySwitch applies GLWE private functional keyswitching on ctIn and returns the result.
func (e Evaluator[T]) PrivateFunctionalGLWEKeySwitch(ctIn []LWECiphertext[T], pfksk PrivateFunctionalGLWEKeySwitchKey[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PrivateFunctionalGLWEKeySwitchAssign(ctIn, pfksk, ctOut)
	return ctOut
}

// PrivateFunctionalGLWEKeySwitchAssign applies GLWE private functional keyswitching on ctIn and writes it to ctOut.
func (e Evaluator[T]) PrivateFunctionalGLWEKeySwitchAssign(ctIn []LWECiphertext[T], pfksk PrivateFunctionalGLWEKeySwitchKey[T], ctOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(pfksk.decompParams)
	for i := 0; i < pfksk.InputCount(); i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			e.DecomposeAssign(ctIn[i].Value[j], buffDecomposed, pfksk.decompParams)
			for k := 0; k < pfksk.decompParams.level; k++ {
				if i == 0 && j == 0 && k == 0 {
					e.ScalarMulGLWEAssign(pfksk.Value[i][j].Value[k], -buffDecomposed[k], ctOut)
				} else {
					e.ScalarMulSubGLWEAssign(pfksk.Value[i][j].Value[k], buffDecomposed[k], ctOut)
				}
			}
		}
	}
}

// PublicFunctionalLWEKeySwitch applies LWE public functional keyswitching on ctIn and returns the result.
//
// The function f has the form f(in []T) T,
// where length of in is always len(ctIn).
func (e Evaluator[T]) PublicFunctionalLWEKeySwitch(ctIn []LWECiphertext[T], f func([]T) T, pfksk PublicFunctionalLWEKeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.PublicFunctionalLWEKeySwitchAssign(ctIn, f, pfksk, ctOut)
	return ctOut
}

// PublicFunctionalLWEKeySwitchAssign applies LWE public functional keyswitching on ctIn and writes it to ctOut.
//
// The function f has the form f(in []T) T,
// where length of in is always len(ctIn).
func (e Evaluator[T]) PublicFunctionalLWEKeySwitchAssign(ctIn []LWECiphertext[T], f func([]T) T, pfksk PublicFunctionalLWEKeySwitchKey[T], ctOut LWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(pfksk.decompParams)

	in := make([]T, len(ctIn))
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j, ct := range ctIn {
			in[j] = ct.Value[i+1]
		}
		e.DecomposeAssign(f(in), buffDecomposed, pfksk.decompParams)
		for j := 0; j < pfksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.ScalarMulLWEAssign(pfksk.Value[i].Value[j], -buffDecomposed[j], ctOut)
			} else {
				e.ScalarMulSubLWEAssign(pfksk.Value[i].Value[j], buffDecomposed[j], ctOut)
			}
		}
	}

	for i, ct := range ctIn {
		in[i] = ct.Value[0]
	}
	ctOut.Value[0] += f(in)
}

// PublicFunctionalGLWEKeySwitch applies GLWE public functional keyswitching on ctIn and returns the result.
//
// The function f has the form f(in []T, out Poly[T]),
// where length of in is always inputCount.
// The initial value of out is undefined.
func (e Evaluator[T]) PublicFunctionalGLWEKeySwitch(ctIn []LWECiphertext[T], f func([]T, poly.Poly[T]), pfksk PublicFunctionalGLWEKeySwitchKey[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PublicFunctionalGLWEKeySwitchAssign(ctIn, f, pfksk, ctOut)
	return ctOut
}

// PublicFunctionalGLWEKeySwitchAssign applies GLWE public functional keyswitching on ctIn and writes it to ctOut.
//
// The function f has the form f(in []T, out Poly[T]),
// where length of in is always inputCount.
// The initial value of out is undefined.
func (e Evaluator[T]) PublicFunctionalGLWEKeySwitchAssign(ctIn []LWECiphertext[T], f func([]T, poly.Poly[T]), pfksk PublicFunctionalGLWEKeySwitchKey[T], ctOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(pfksk.decompParams)
	in := make([]T, len(ctIn))
	out := poly.New[T](e.Parameters.polyDegree)

	fourierCtOut := NewFourierGLWECiphertext(e.Parameters)
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j, ct := range ctIn {
			in[j] = ct.Value[i+1]
		}
		f(in, out)
		e.DecomposePolyAssign(out, buffDecomposed, pfksk.decompParams)
		for j := 0; j < pfksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEAssign(pfksk.Value[i].Value[j], buffDecomposed[j], fourierCtOut)
				e.NegFourierGLWEAssign(fourierCtOut, fourierCtOut)
			} else {
				e.PolyMulSubFourierGLWEAssign(pfksk.Value[i].Value[j], buffDecomposed[j], fourierCtOut)
			}
		}
	}

	e.ToStandardGLWECiphertextAssign(fourierCtOut, ctOut)

	for i, ct := range ctIn {
		in[i] = ct.Value[0]
	}
	f(in, out)
	e.PolyEvaluator.AddAssign(ctOut.Value[0], out, ctOut.Value[0])
}

// PackingPublicFunctionalKeySwitch is a special instance of public functional keyswitching with packing function.
func (e Evaluator[T]) PackingPublicFunctionalKeySwitch(ctIn []LWECiphertext[T], pfksk PublicFunctionalGLWEKeySwitchKey[T]) GLWECiphertext[T] {
	f := func(in []T, out poly.Poly[T]) {
		for i := 0; i < len(ctIn); i++ {
			out.Coeffs[i] = in[i]
		}
		for i := len(ctIn); i < out.Degree(); i++ {
			out.Coeffs[i] = 0
		}
	}

	return e.PublicFunctionalGLWEKeySwitch(ctIn, f, pfksk)
}

// CircuitBootstrap computes circuit bootstrapping.
func (e Evaluator[T]) CircuitBootstrap(ct LWECiphertext[T], decompParams DecompositionParameters[T], cbsk CircuitBootstrapKey[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, decompParams)
	e.CircuitBootstrapAssign(ct, cbsk, ctOut)
	return ctOut
}

// CircuitBootstrapAssign computes circuit bootstrapping and writes the result to ctOut.
func (e Evaluator[T]) CircuitBootstrapAssign(ct LWECiphertext[T], cbsk CircuitBootstrapKey[T], ctOut GGSWCiphertext[T]) {
	levelCt := NewLWECiphertext(e.Parameters)
	for i := 0; i < ctOut.decompParams.level; i++ {
		e.GenLookUpTableFullAssign(func(x int) T { return T(x) << ctOut.decompParams.ScaledBaseLog(i) }, e.buffer.lut)
		e.BootstrapLUTAssign(ct, e.buffer.lut, levelCt)
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.PrivateFunctionalGLWEKeySwitchAssign([]LWECiphertext[T]{levelCt}, cbsk.Value[j], ctOut.Value[j].Value[i])
		}
	}
}

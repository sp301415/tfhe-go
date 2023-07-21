package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// PrivataeFunctionalLWEKeySwitch applies LWE private functional keyswitching on ctIn and returns the result.
func (e Evaluater[T]) PrivateFunctionalLWEKeySwitch(ctIn []LWECiphertext[T], pfksk PrivateFunctionalLWEKeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.PrivateFunctionalLWEKeySwitchInPlace(ctIn, pfksk, ctOut)
	return ctOut
}

// PrivateFunctionalLWEKeySwitchInPlace applies LWE private functional keyswitching on ctIn and writes it to ctOut.
func (e Evaluater[T]) PrivateFunctionalLWEKeySwitchInPlace(ctIn []LWECiphertext[T], pfksk PrivateFunctionalLWEKeySwitchKey[T], ctOut LWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(pfksk.decompParams)
	for i := 0; i < pfksk.InputCount(); i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			e.DecomposeInPlace(ctIn[i].Value[j], buffDecomposed, pfksk.decompParams)
			for k := 0; k < pfksk.decompParams.level; k++ {
				if i == 0 && j == 0 && k == 0 {
					e.ScalarMulLWEInPlace(pfksk.Value[i].Value[j].Value[k], -buffDecomposed[k], ctOut)
				} else {
					e.ScalarMulSubLWEInPlace(pfksk.Value[i].Value[j].Value[k], buffDecomposed[k], ctOut)
				}
			}
		}
	}
}

// PrivateFunctionalGLWEKeySwitch applies GLWE private functional keyswitching on ctIn and returns the result.
func (e Evaluater[T]) PrivateFunctionalGLWEKeySwitch(ctIn []LWECiphertext[T], pfksk PrivateFunctionalGLWEKeySwitchKey[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PrivateFunctionalGLWEKeySwitchInPlace(ctIn, pfksk, ctOut)
	return ctOut
}

// PrivateFunctionalGLWEKeySwitchInPlace applies GLWE private functional keyswitching on ctIn and writes it to ctOut.
func (e Evaluater[T]) PrivateFunctionalGLWEKeySwitchInPlace(ctIn []LWECiphertext[T], pfksk PrivateFunctionalGLWEKeySwitchKey[T], ctOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(pfksk.decompParams)
	for i := 0; i < pfksk.InputCount(); i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			e.DecomposeInPlace(ctIn[i].Value[j], buffDecomposed, pfksk.decompParams)
			for k := 0; k < pfksk.decompParams.level; k++ {
				if i == 0 && j == 0 && k == 0 {
					e.ScalarMulGLWEInPlace(pfksk.Value[i][j].Value[k], -buffDecomposed[k], ctOut)
				} else {
					e.ScalarMulSubGLWEInPlace(pfksk.Value[i][j].Value[k], buffDecomposed[k], ctOut)
				}
			}
		}
	}
}

// PublicFunctionalLWEKeySwitch applies LWE public functional keyswitching on ctIn and returns the result.
//
// The function f has the form f(in []T) T,
// where length of in is always len(ctIn).
func (e Evaluater[T]) PublicFunctionalLWEKeySwitch(ctIn []LWECiphertext[T], f func([]T) T, pfksk PublicFunctionalLWEKeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.PublicFunctionalLWEKeySwitchInPlace(ctIn, f, pfksk, ctOut)
	return ctOut
}

// PublicFunctionalLWEKeySwitchInPlace applies LWE public functional keyswitching on ctIn and writes it to ctOut.
//
// The function f has the form f(in []T) T,
// where length of in is always len(ctIn).
func (e Evaluater[T]) PublicFunctionalLWEKeySwitchInPlace(ctIn []LWECiphertext[T], f func([]T) T, pfksk PublicFunctionalLWEKeySwitchKey[T], ctOut LWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(pfksk.decompParams)

	in := make([]T, len(ctIn))
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j, ct := range ctIn {
			in[j] = ct.Value[i+1]
		}
		e.DecomposeInPlace(f(in), buffDecomposed, pfksk.decompParams)
		for j := 0; j < pfksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.ScalarMulLWEInPlace(pfksk.Value[i].Value[j], -buffDecomposed[j], ctOut)
			} else {
				e.ScalarMulSubLWEInPlace(pfksk.Value[i].Value[j], buffDecomposed[j], ctOut)
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
func (e Evaluater[T]) PublicFunctionalGLWEKeySwitch(ctIn []LWECiphertext[T], f func([]T, poly.Poly[T]), pfksk PublicFunctionalGLWEKeySwitchKey[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PublicFunctionalGLWEKeySwitchInPlace(ctIn, f, pfksk, ctOut)
	return ctOut
}

// PublicFunctionalGLWEKeySwitchInPlace applies GLWE public functional keyswitching on ctIn and writes it to ctOut.
//
// The function f has the form f(in []T, out Poly[T]),
// where length of in is always inputCount.
// The initial value of out is undefined.
func (e Evaluater[T]) PublicFunctionalGLWEKeySwitchInPlace(ctIn []LWECiphertext[T], f func([]T, poly.Poly[T]), pfksk PublicFunctionalGLWEKeySwitchKey[T], ctOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(pfksk.decompParams)
	in := make([]T, len(ctIn))
	out := poly.New[T](e.Parameters.polyDegree)

	fourierCtOut := NewFourierGLWECiphertext(e.Parameters)
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j, ct := range ctIn {
			in[j] = ct.Value[i+1]
		}
		f(in, out)
		e.DecomposePolyInplace(out, buffDecomposed, pfksk.decompParams)
		for j := 0; j < pfksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEInPlace(pfksk.Value[i].Value[j], buffDecomposed[j], fourierCtOut)
				e.NegFourierGLWEInPlace(fourierCtOut, fourierCtOut)
			} else {
				e.PolyMulSubFourierGLWEInPlace(pfksk.Value[i].Value[j], buffDecomposed[j], fourierCtOut)
			}
		}
	}

	e.ToStandardGLWECiphertextInPlace(fourierCtOut, ctOut)

	for i, ct := range ctIn {
		in[i] = ct.Value[0]
	}
	f(in, out)
	e.PolyEvaluater.AddInPlace(ctOut.Value[0], out, ctOut.Value[0])
}

// PackingPublicFunctionalKeySwitch is a special instance of public functional keyswitching with packing function.
func (e Evaluater[T]) PackingPublicFunctionalKeySwitch(ctIn []LWECiphertext[T], pfksk PublicFunctionalGLWEKeySwitchKey[T]) GLWECiphertext[T] {
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
func (e Evaluater[T]) CircuitBootstrap(ct LWECiphertext[T], decompParams DecompositionParameters[T], cbsk CircuitBootstrapKey[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, decompParams)
	e.CircuitBootstrapInPlace(ct, cbsk, ctOut)
	return ctOut
}

// CircuitBootstrapInPlace computes circuit bootstrapping and writes the result to ctOut.
func (e Evaluater[T]) CircuitBootstrapInPlace(ct LWECiphertext[T], cbsk CircuitBootstrapKey[T], ctOut GGSWCiphertext[T]) {
	levelCt := NewLWECiphertext(e.Parameters)
	for i := 0; i < ctOut.decompParams.level; i++ {
		e.GenLookUpTableFullInPlace(func(x int) T { return T(x) << ctOut.decompParams.ScaledBaseLog(i) }, e.buffer.lut)
		e.BootstrapLUTInPlace(ct, e.buffer.lut, levelCt)
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.PrivateFunctionalGLWEKeySwitchInPlace([]LWECiphertext[T]{levelCt}, cbsk.Value[j], ctOut.Value[j].Value[i])
		}
	}
}

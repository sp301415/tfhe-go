package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// FourierGLWECiphertext is a GLWE ciphertext with FFT pre-applied.
type FourierGLWECiphertext struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWEDimension + 1.
	Value []poly.FourierPoly
}

// NewFourierGLWECiphertext allocates an empty FourierGLWECiphertext.
func NewFourierGLWECiphertext[T Tint](params Parameters[T]) FourierGLWECiphertext {
	ct := make([]poly.FourierPoly, params.glweDimension+1)
	for i := range ct {
		ct[i] = poly.NewFourierPoly(params.polyDegree)
	}
	return FourierGLWECiphertext{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGLWECiphertext) Copy() FourierGLWECiphertext {
	ctCopy := make([]poly.FourierPoly, len(ct.Value))
	for i := range ctCopy {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGLWECiphertext{Value: ctCopy}
}

// BootstrappingKey is a key for bootstrapping.
// Essentially, this is a GGSW encryption of LWE key with GLWE key.
// However, FFT is already applied for fast external product.
type BootstrappingKey[T Tint] struct {
	// Value is ordered as [LWEDimension][GLWEDimension+1][Level]FourierGLWECiphertext.
	Value [][][]FourierGLWECiphertext

	decompParams DecompositionParameters[T]
}

// NewBootstrappingKey allocates an empty BootstrappingKey.
func NewBootstrappingKey[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) BootstrappingKey[T] {
	bsk := make([][][]FourierGLWECiphertext, params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		bsk[i] = make([][]FourierGLWECiphertext, params.glweDimension+1)
		for j := 0; j < params.glweDimension+1; j++ {
			bsk[i][j] = make([]FourierGLWECiphertext, decompParams.level)
			for k := 0; k < decompParams.level; k++ {
				bsk[i][j][k] = NewFourierGLWECiphertext(params)
			}
		}
	}
	return BootstrappingKey[T]{Value: bsk, decompParams: decompParams}
}

// Copy returns a copy of the key.
func (bsk BootstrappingKey[T]) Copy() BootstrappingKey[T] {
	bskCopy := make([][][]FourierGLWECiphertext, len(bsk.Value))
	for i := range bsk.Value {
		bskCopy[i] = make([][]FourierGLWECiphertext, len(bsk.Value[i]))
		for j := range bsk.Value[i] {
			bskCopy[i][j] = make([]FourierGLWECiphertext, len(bsk.Value[i][j]))
			for k := range bsk.Value[i][j] {
				bskCopy[i][j][k] = bsk.Value[i][j][k].Copy()
			}
		}
	}
	return BootstrappingKey[T]{Value: bskCopy, decompParams: bsk.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the key.
func (bsk BootstrappingKey[T]) DecompositionParameters() DecompositionParameters[T] {
	return bsk.decompParams
}

// KeySwitchingKey is a LWE keyswitching key from GLWE secret key to LWE secret key.
// Essentially, this is a GSW encryption of GLWE key with LWE key.
type KeySwitchingKey[T Tint] GSWCiphertext[T]

// NewKeySwitchingKey allocates an empty KeySwitchingKey.
func NewKeySwitchingKey[T Tint](inputDimension, outputDimension int, decompParams DecompositionParameters[T]) KeySwitchingKey[T] {
	kswKey := make([]LevCiphertext[T], inputDimension)
	for i := 0; i < inputDimension; i++ {
		kswKey[i] = LevCiphertext[T]{Value: make([]LWECiphertext[T], decompParams.level), decompParams: decompParams}
		for j := 0; j < decompParams.level; j++ {
			kswKey[i].Value[j] = LWECiphertext[T]{Value: make([]T, outputDimension+1)}
		}
	}
	return KeySwitchingKey[T]{Value: kswKey, decompParams: decompParams}
}

// InputLWEDimension returns the input LWEDimension of this key.
func (ksk KeySwitchingKey[T]) InputLWEDimension() int {
	return len(ksk.Value)
}

// OutputLWEDimension returns the output LWEDimension of this key.
func (ksk KeySwitchingKey[T]) OutputLWEDimension() int {
	return len(ksk.Value[0].Value[0].Value) - 1
}

// Copy returns a copy of the key.
func (ksk KeySwitchingKey[T]) Copy() KeySwitchingKey[T] {
	return KeySwitchingKey[T](GSWCiphertext[T](ksk).Copy())
}

// SampleExtract extracts LWE ciphertext of index i from GLWE ciphertext and returns it.
// The output ciphertext has length GLWEDimension * PolyDegree + 1.
func (e Evaluater[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, e.Parameters.glweDimension*e.Parameters.polyDegree+1)}
	e.SampleExtractInPlace(ct, index, ctOut)
	return ctOut
}

// SampleExtractInPlace extracts LWE ciphertext of index from GLWE ciphertext.
// The output ciphertext should have length GLWEDimension * PolyDegree + 1.
func (e Evaluater[T]) SampleExtractInPlace(ct GLWECiphertext[T], index int, ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0].Coeffs[index]

	ctMask, ctOutMask := ct.Value[1:], ctOut.Value[1:]
	for i := 0; i < e.Parameters.glweDimension; i++ {
		start := i * e.Parameters.polyDegree
		end := (i + 1) * e.Parameters.polyDegree

		// Reverse polynomial coefficient of ctMask, and save it to ctOutMask
		vec.ReverseInPlace(ctMask[i].Coeffs, ctOutMask[start:end])

		// We rotate to right index + 1 times,
		// and negate index+1 ~ PolyDegree values.
		vec.RotateAssign(ctOutMask[start:end], index+1)
		vec.NegAssign(ctOutMask[start+index+1 : end])
	}
}

// KeySwitch switches key of ct, and returns a new ciphertext.
func (e Evaluater[T]) KeySwitch(ct LWECiphertext[T], ksk KeySwitchingKey[T]) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, ksk.OutputLWEDimension()+1)}
	e.KeySwitchInPlace(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchInPlace switches key of ct, and saves it to ctOut.
func (e Evaluater[T]) KeySwitchInPlace(ct LWECiphertext[T], ksk KeySwitchingKey[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0] // ct = (b, 0, ...)

	for i := 0; i < ksk.OutputLWEDimension(); i++ {
		decomposedMask := e.Decompose(ct.Value[i+1], ksk.decompParams)
		for j := 0; j < ksk.decompParams.level; j++ {
			vec.ScalarMulSubAssign(ksk.Value[i].Value[j].Value, decomposedMask[j], ctOut.Value)
		}
	}
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's bootstrapping key.
// Input ciphertext should be length GLWEDimension + 1, and output ciphertext will be length LWEDimension + 1.
func (e Evaluater[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	return e.KeySwitch(ct, e.evaluationKey.KeySwitchingKey)
}

// KeySwitchForBootstrapInPlace performs the keyswitching using evaulater's bootstrapping key.
// Input ciphertext should be length GLWEDimension + 1, and output ciphertext should be length LWEDimension + 1.
func (e Evaluater[T]) KeySwitchForBootstrapInPlace(ct, ctOut LWECiphertext[T]) {
	e.KeySwitchInPlace(ct, e.evaluationKey.KeySwitchingKey, ctOut)
}

package tfhe

import "github.com/sp301415/tfhe/math/poly"

// FourierGLWECiphertext is a GLWE ciphertext with FFT pre-applied.
type FourierGLWECiphertext struct {
	Mask []poly.FourierPoly
	Body poly.FourierPoly
}

// NewFourierGLWECiphertext allocates an empty FourierGLWECiphertext.
func NewFourierGLWECiphertext[T Tint](params Parameters[T]) FourierGLWECiphertext {
	mask := make([]poly.FourierPoly, params.glweDimension)
	for i := range mask {
		mask[i] = poly.NewFourierPoly(params.polyDegree)
	}
	return FourierGLWECiphertext{Mask: mask, Body: poly.NewFourierPoly(params.polyDegree)}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGLWECiphertext) Copy() FourierGLWECiphertext {
	maskCopy := make([]poly.FourierPoly, ct.Len())
	for i := range maskCopy {
		maskCopy[i] = ct.Mask[i].Copy()
	}
	return FourierGLWECiphertext{Mask: maskCopy, Body: ct.Body.Copy()}
}

// Len returns the length of the ciphertext.
func (ct FourierGLWECiphertext) Len() int {
	return len(ct.Mask) + 1
}

// Degree returns the polynomial degree of elements of the ciphertext.
func (ct FourierGLWECiphertext) Degree() int {
	return ct.Mask[0].Degree()
}

// BootstrappingKey is a key for bootstrapping.
// Essentially, this is a GGSW encryption of LWE key with GLWE key.
// However, FFT is already applied for fast external product.
type BootstrappingKey[T Tint] struct {
	// Value is ordered as [n_in][k+1][l]FourierGLWECiphertext.
	Value [][][]FourierGLWECiphertext

	decompParams DecompositionParameters[T]
}

// Copy returns a copy of the key.
func (sk BootstrappingKey[T]) Copy() BootstrappingKey[T] {
	skCopy := make([][][]FourierGLWECiphertext, len(sk.Value))
	for i := range sk.Value {
		skCopy[i] = make([][]FourierGLWECiphertext, len(sk.Value[i]))
		for j := range sk.Value[i] {
			skCopy[i][j] = make([]FourierGLWECiphertext, len(sk.Value[i][j]))
			for k := range sk.Value[i][j] {
				skCopy[i][j][k] = sk.Value[i][j][k].Copy()
			}
		}
	}
	return BootstrappingKey[T]{Value: skCopy, decompParams: sk.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the key.
func (sk BootstrappingKey[T]) DecompositionParameters() DecompositionParameters[T] {
	return sk.decompParams
}

// KeyswitchingKey is a LWE Keyswitching key from GLWE secret key to LWE secret key.
// Essentially, this is a GSW encryption of GLWE key with LWE key.
type KeyswitchingKey[T Tint] GSWCiphertext[T]

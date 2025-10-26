package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// FFTGLWESecretKey is a GLWE key in Fourier domain.
type FFTGLWESecretKey[T TorusInt] struct {
	// Value has length GLWERank.
	Value []poly.FFTPoly
}

// NewFFTGLWESecretKey creates a new FFTGLWESecretKey.
func NewFFTGLWESecretKey[T TorusInt](params Parameters[T]) FFTGLWESecretKey[T] {
	sk := make([]poly.FFTPoly, params.glweRank)
	for i := range sk {
		sk[i] = poly.NewFFTPoly(params.polyRank)
	}
	return FFTGLWESecretKey[T]{Value: sk}
}

// NewFFTGLWESecretKeyCustom creates a new FFTGLWESecretKey with given dimension and polyRank.
func NewFFTGLWESecretKeyCustom[T TorusInt](glweRank, polyRank int) FFTGLWESecretKey[T] {
	sk := make([]poly.FFTPoly, glweRank)
	for i := range sk {
		sk[i] = poly.NewFFTPoly(polyRank)
	}
	return FFTGLWESecretKey[T]{Value: sk}
}

// Copy returns a copy of the key.
func (sk FFTGLWESecretKey[T]) Copy() FFTGLWESecretKey[T] {
	skCopy := make([]poly.FFTPoly, len(sk.Value))
	for i := range skCopy {
		skCopy[i] = sk.Value[i].Copy()
	}
	return FFTGLWESecretKey[T]{Value: skCopy}
}

// CopyFrom copies values from the key.
func (sk *FFTGLWESecretKey[T]) CopyFrom(skIn FFTGLWESecretKey[T]) {
	for i := range sk.Value {
		sk.Value[i].CopyFrom(skIn.Value[i])
	}
}

// Clear clears the key.
func (sk *FFTGLWESecretKey[T]) Clear() {
	for i := range sk.Value {
		sk.Value[i].Clear()
	}
}

// FFTGLWECiphertext is a GLWE ciphertext in Fourier domain.
type FFTGLWECiphertext[T TorusInt] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWERank + 1.
	Value []poly.FFTPoly
}

// NewFFTGLWECiphertext creates a new FFTGLWECiphertext.
func NewFFTGLWECiphertext[T TorusInt](params Parameters[T]) FFTGLWECiphertext[T] {
	ct := make([]poly.FFTPoly, params.glweRank+1)
	for i := range ct {
		ct[i] = poly.NewFFTPoly(params.polyRank)
	}
	return FFTGLWECiphertext[T]{Value: ct}
}

// NewFFTGLWECiphertextCustom creates a new FFTGLWECiphertext with given dimension and polyRank.
func NewFFTGLWECiphertextCustom[T TorusInt](glweRank, polyRank int) FFTGLWECiphertext[T] {
	ct := make([]poly.FFTPoly, glweRank+1)
	for i := range ct {
		ct[i] = poly.NewFFTPoly(polyRank)
	}
	return FFTGLWECiphertext[T]{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct FFTGLWECiphertext[T]) Copy() FFTGLWECiphertext[T] {
	ctCopy := make([]poly.FFTPoly, len(ct.Value))
	for i := range ctCopy {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FFTGLWECiphertext[T]{Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *FFTGLWECiphertext[T]) CopyFrom(ctIn FFTGLWECiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// Clear clears the ciphertext.
func (ct *FFTGLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// FFTGLevCiphertext is a leveled GLWE ciphertext in Fourier domain.
type FFTGLevCiphertext[T TorusInt] struct {
	GadgetParams GadgetParameters[T]

	// Value has length Level.
	Value []FFTGLWECiphertext[T]
}

// NewFFTGLevCiphertext creates a new FFTGLevCiphertext.
func NewFFTGLevCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) FFTGLevCiphertext[T] {
	ct := make([]FFTGLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewFFTGLWECiphertext(params)
	}
	return FFTGLevCiphertext[T]{Value: ct, GadgetParams: gadgetParams}
}

// NewFFTGLevCiphertextCustom creates a new FFTGLevCiphertext with given dimension and polyRank.
func NewFFTGLevCiphertextCustom[T TorusInt](glweRank, polyRank int, gadgetParams GadgetParameters[T]) FFTGLevCiphertext[T] {
	ct := make([]FFTGLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewFFTGLWECiphertextCustom[T](glweRank, polyRank)
	}
	return FFTGLevCiphertext[T]{Value: ct, GadgetParams: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct FFTGLevCiphertext[T]) Copy() FFTGLevCiphertext[T] {
	ctCopy := make([]FFTGLWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FFTGLevCiphertext[T]{Value: ctCopy, GadgetParams: ct.GadgetParams}
}

// CopyFrom copies values from the ciphertext.
func (ct *FFTGLevCiphertext[T]) CopyFrom(ctIn FFTGLevCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParams = ctIn.GadgetParams
}

// Clear clears the ciphertext.
func (ct *FFTGLevCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// FFTGGSWCiphertext represents an encrypted GGSW ciphertext in Fourier domain.
type FFTGGSWCiphertext[T TorusInt] struct {
	GadgetParams GadgetParameters[T]

	// Value has length GLWERank + 1.
	Value []FFTGLevCiphertext[T]
}

// NewFFTGGSWCiphertext creates a new GGSW ciphertext.
func NewFFTGGSWCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) FFTGGSWCiphertext[T] {
	ct := make([]FFTGLevCiphertext[T], params.glweRank+1)
	for i := 0; i < params.glweRank+1; i++ {
		ct[i] = NewFFTGLevCiphertext(params, gadgetParams)
	}
	return FFTGGSWCiphertext[T]{Value: ct, GadgetParams: gadgetParams}
}

// NewFFTGGSWCiphertextCustom creates a new GGSW ciphertext with given dimension and polyRank.
func NewFFTGGSWCiphertextCustom[T TorusInt](glweRank, polyRank int, gadgetParams GadgetParameters[T]) FFTGGSWCiphertext[T] {
	ct := make([]FFTGLevCiphertext[T], glweRank+1)
	for i := 0; i < glweRank+1; i++ {
		ct[i] = NewFFTGLevCiphertextCustom(glweRank, polyRank, gadgetParams)
	}
	return FFTGGSWCiphertext[T]{Value: ct, GadgetParams: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct FFTGGSWCiphertext[T]) Copy() FFTGGSWCiphertext[T] {
	ctCopy := make([]FFTGLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FFTGGSWCiphertext[T]{Value: ctCopy, GadgetParams: ct.GadgetParams}
}

// CopyFrom copies values from the ciphertext.
func (ct *FFTGGSWCiphertext[T]) CopyFrom(ctIn FFTGGSWCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParams = ctIn.GadgetParams
}

// Clear clears the ciphertext.
func (ct *FFTGGSWCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

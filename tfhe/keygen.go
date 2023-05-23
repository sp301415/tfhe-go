package tfhe

// GenLWEKey samples a new LWE key.
func (e Encrypter[T]) GenLWEKey() LWEKey[T] {
	sk := NewLWEKey(e.Parameters)
	e.binarySampler.SampleSliceAssign(sk.Value)
	return sk
}

// GenGLWEKey samples a new GLWE key.
func (e Encrypter[T]) GenGLWEKey() GLWEKey[T] {
	sk := NewGLWEKey(e.Parameters)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.binarySampler.SamplePolyAssign(sk.Value[i])
	}
	return sk
}

package tfhe

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
					e.ScalarMulSubLWEAssign(pfksk.Value[i].Value[j].Value[k], buffDecomposed[k], ctOut)
				}
			}
		}
	}
}

// PrivataeFunctionalGLWEKeySwitch applies GLWE private functional keyswitching on ctIn and returns the result.
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
					e.ScalarMulSubGLWEAssign(pfksk.Value[i][j].Value[k], buffDecomposed[k], ctOut)
				}
			}
		}
	}
}

package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
	"github.com/sp301415/tfhe/math/vec"
)

// Encrypter encrypts and decrypts values.
// This is meant to be a private struct.
type Encrypter[T Tint] struct {
	Parameters Parameters[T]

	uniformSampler rand.UniformSampler[T]
	binarySampler  rand.BinarySampler[T]
	lweSampler     rand.GaussianSampler[T]
	glweSampler    rand.GaussianSampler[T]

	polyEvaluator poly.Evaluater[T]

	lweKey  LWESecretKey[T]
	glweKey GLWESecretKey[T]

	// buffGLWEPlaintext is used to store intermediate Plaintext values
	// especially in GGSW computation.
	buffGLWEPlaintext poly.Poly[T]
}

// NewEncrypter returns the initialized encrypter with given parameters.
func NewEncrypter[T Tint](params Parameters[T]) Encrypter[T] {
	uniformSampler := rand.UniformSampler[T]{}
	binarySampler := rand.BinarySampler[T]{}
	lweSampler := rand.GaussianSampler[T]{StdDev: params.lweStdDev * float64(num.MaxT[T]())}
	glweSampler := rand.GaussianSampler[T]{StdDev: params.glweStdDev * float64(num.MaxT[T]())}

	// Sample binary LWE key
	lweKey := NewLWESecretKey(params)
	binarySampler.SampleSlice(lweKey.Value)

	// Sample binary GLWE key
	glweKey := NewGLWESecretKey(params)
	for i := 0; i < params.glweDimension; i++ {
		binarySampler.SamplePoly(glweKey.Value[i])
	}

	return Encrypter[T]{
		Parameters: params,

		uniformSampler: uniformSampler,
		binarySampler:  binarySampler,
		lweSampler:     lweSampler,
		glweSampler:    glweSampler,

		polyEvaluator: poly.NewEvaluater[T](params.polyDegree),

		lweKey:  lweKey,
		glweKey: glweKey,

		buffGLWEPlaintext: poly.New[T](params.polyDegree),
	}
}

// SampleEvaluationKey samples a new SampleEvaluationKey, used for Evaluater.
func (e Encrypter[T]) SampleEvaluationKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrappingKey: e.SampleBootstrappingKey(),
		KeyswitchingKey:  e.SampleKeySwitchingKey(),
	}
}

// SampleBootstrappingKey samples a new bootstrapping key for bootstrapping.
func (e Encrypter[T]) SampleBootstrappingKey() BootstrappingKey[T] {
	decompParams := e.Parameters.pbsParameters

	// Allocate BootstrappingKey, but not FourierPoly.
	bsKey := make([][][]FourierGLWECiphertext, e.Parameters.lweDimension)
	for i := 0; i < e.Parameters.lweDimension; i++ {
		bsKey[i] = make([][]FourierGLWECiphertext, e.Parameters.glweDimension+1)
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			bsKey[i][j] = make([]FourierGLWECiphertext, decompParams.level)
			for k := 0; k < decompParams.level; k++ {
				bsKey[i][j][k] = FourierGLWECiphertext{Mask: make([]poly.FourierPoly, e.Parameters.glweDimension)}
			}
		}
	}

	// Now, we fill the bootstrapping key...
	// We encrypt -S_j * s_i * Q / base^(k+1)
	buffCt := NewGLWECiphertext(e.Parameters)
	factor := T(1 << (decompParams.maxBits - decompParams.baseLog))
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			if j < e.Parameters.glweDimension {
				e.buffGLWEPlaintext.CopyFrom(e.glweKey.Value[j]) // buff = S_j
				e.polyEvaluator.NegAssign(e.buffGLWEPlaintext)   // buff = -S_j
			} else {
				// Just buff = 1
				e.buffGLWEPlaintext.Clear()
				e.buffGLWEPlaintext.Coeffs[0] = 1
			}
			e.polyEvaluator.ScalarMulAssign(e.lweKey.Value[i]*factor, e.buffGLWEPlaintext) // buff = -S_j * s_i * Q / base

			for k := 0; k < decompParams.level; k++ {
				e.EncryptGLWEInPlace(GLWEPlaintext[T]{Value: e.buffGLWEPlaintext}, buffCt)

				for l := 0; l < e.Parameters.glweDimension; l++ {
					bsKey[i][j][k].Mask[l] = e.polyEvaluator.ToFourierPoly(buffCt.Mask[l])
				}
				bsKey[i][j][k].Body = e.polyEvaluator.ToFourierPoly(buffCt.Body)

				if k < decompParams.level-1 { // Skip last loop
					e.polyEvaluator.ScalarDivAssign(decompParams.base, e.buffGLWEPlaintext)
				}
			}
		}
	}

	return BootstrappingKey[T]{Value: bsKey, decompParams: e.Parameters.pbsParameters}
}

// SampleKeySwitchingKey samples a new keyswitching key for bootsrapping.
func (e Encrypter[T]) SampleKeySwitchingKey() KeyswitchingKey[T] {
	kswKeyLength := e.Parameters.glweDimension * e.Parameters.polyDegree // Length of key_in: GLWEDimension * PolyDegree
	kswKey := make([][]LWECiphertext[T], kswKeyLength)
	for i := 0; i < kswKeyLength; i++ {
		keyIdx, pIdx := i/e.Parameters.polyDegree, i%e.Parameters.polyDegree
		skIn := e.glweKey.Value[keyIdx].Coeffs[pIdx]

		e.EncryptLevInPlace(LWEPlaintext[T]{Value: skIn}, e.Parameters.keyswitchParameters, kswKey[i])
	}

	return KeyswitchingKey[T]{Value: kswKey}
}

// LWESecretKey returns a copy of LWE secret key.
func (e Encrypter[T]) LWESecretKey() LWESecretKey[T] {
	return e.lweKey.Copy()
}

// GLWESecretKey returns a copy of GLWE secret key.
func (e Encrypter[T]) GLWESecretKey() GLWESecretKey[T] {
	return e.glweKey.Copy()
}

// EncodeLWE encodes an integer message to LWE plaintext.
// Message will get wrapped around Parameters.MessageModulus.
func (e Encrypter[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) * e.Parameters.delta}
}

// DecodeLWE deocdes the LWE plaintext into integer message.
func (e Encrypter[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return int(num.RoundRatioBits(pt.Value, e.Parameters.deltaLog) % e.Parameters.messageModulus)
}

// Encrypt encrypts an integer message to LWE ciphertext.
// Message will get wrapped around Parameters.MessageModulus.
func (e Encrypter[T]) Encrypt(message int) LWECiphertext[T] {
	return e.EncryptLWE(e.EncodeLWE(message))
}

// EncryptLWE encrypts a LWE plaintext to LWE ciphertext.
func (e Encrypter[T]) EncryptLWE(pt LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEInPlace(pt, ct)
	return ct
}

// EncryptLWEInPlace encrypts pt and saves it to ct.
func (e Encrypter[T]) EncryptLWEInPlace(pt LWEPlaintext[T], ct LWECiphertext[T]) {
	// ct = (a_1, ..., a_n, b = <a, s> + pt + e)
	e.uniformSampler.SampleSlice(ct.Mask)
	*ct.Body = vec.Dot(ct.Mask, e.lweKey.Value) + pt.Value + e.lweSampler.Sample()
}

// EncryptLevInPlace encrypts a LWE plaintext to leveled LWE ciphertext.
//
// Panics if decompParams is invalid.
func (e Encrypter[T]) EncryptLevInPlace(pt LWEPlaintext[T], decompParams DecompositionParameters[T], ct []LWECiphertext[T]) {
	for i := 0; i < decompParams.level; i++ {
		factor := T(1 << (decompParams.maxBits - (i+1)*decompParams.baseLog))
		e.EncryptLWEInPlace(LWEPlaintext[T]{Value: factor * pt.Value}, ct[i])
	}
}

// Decrypt decrypts a LWE ciphertext to integer message.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) Decrypt(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWE(ct))
}

// DecryptLWE decrypts a LWE ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) LWEPlaintext[T] {
	// pt = b - <a, s>
	pt := *ct.Body - vec.Dot(ct.Mask, e.lweKey.Value)
	return LWEPlaintext[T]{Value: pt}
}

// DecryptLevInPlace decrypts leveled LWE ciphertexts to LWE plaintext.
//
// Panics if decompParams is invalid, or input Lev is inconsistent with decompParams.
func (e Encrypter[T]) DecryptLev(ct []LWECiphertext[T], decompParams DecompositionParameters[T]) LWEPlaintext[T] {
	lweCt := ct[decompParams.level-1] // Pick the last level
	pt := e.DecryptLWE(lweCt)
	return LWEPlaintext[T]{Value: num.RoundRatioBits(pt.Value, decompParams.maxBits-decompParams.level*decompParams.baseLog)}
}

// EncodeGLWE encodes up to Parameters.PolyDegree integer messages into one GLWE plaintext.
//
// If len(messages) < Parameters.PolyDegree, the leftovers are padded with zero.
// If len(messages) > Parameters.PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncodeGLWE(messages []int) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i, message := range messages {
		if i >= e.Parameters.polyDegree {
			break
		}
		pt.Value.Coeffs[i] = (T(message) % e.Parameters.messageModulus) * e.Parameters.delta
	}
	return pt
}

// DecodeGLWE decodes a GLWE plaintext to integer messages.
func (e Encrypter[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatioBits(pt.Value.Coeffs[i], e.Parameters.deltaLog) % e.Parameters.messageModulus)
	}
	return messages
}

// EncryptPacked encrypts up to Parameters.PolyDegree integer messages into one GLWE ciphertext.
// However, there are not much to do with GLWE ciphertext, so this is only useful
// when you want to reduce communication costs.
//
// If len(messages) < Parameters.PolyDegree, the leftovers are padded with zero.
// If len(messages) > Parameters.PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncryptPacked(messages []int) GLWECiphertext[T] {
	return e.EncryptGLWE(e.EncodeGLWE(messages))
}

// EncryptGLWE encrypts a GLWE plaintext to GLWE ciphertext.
func (e Encrypter[T]) EncryptGLWE(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEInPlace(pt, ct)
	return ct
}

// EncryptGLWEInPlace encrypts pt and saves it to ct.
func (e Encrypter[T]) EncryptGLWEInPlace(pt GLWEPlaintext[T], ct GLWECiphertext[T]) {
	// ct = (a_1, ..., a_k, b = sum a*s + pt + e)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.glweSampler.SamplePoly(ct.Mask[i])
	}

	e.glweSampler.SamplePoly(ct.Body)
	e.polyEvaluator.AddAssign(pt.Value, ct.Body)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluator.MulAddAssign(ct.Mask[i], e.glweKey.Value[i], ct.Body)
	}
}

// EncryptGLevInPlace encrypts GLWE plaintext to leveled GLWE ciphertexts.
//
// Panics if decompParams is invalid.
func (e Encrypter[T]) EncryptGLevInPlace(pt GLWEPlaintext[T], decompParams DecompositionParameters[T], ct []GLWECiphertext[T]) {
	factor := T(1 << (decompParams.maxBits - decompParams.baseLog))
	e.polyEvaluator.ScalarMulInPlace(pt.Value, factor, e.buffGLWEPlaintext)
	for i := 0; i < decompParams.level; i++ {
		e.EncryptGLWEInPlace(GLWEPlaintext[T]{Value: e.buffGLWEPlaintext}, ct[i])
		if i < decompParams.level-1 { // Skip last loop
			e.polyEvaluator.ScalarDivAssign(decompParams.base, e.buffGLWEPlaintext)
		}
	}
}

// DecryptPacked decrypts a GLWE ciphertext to integer messages.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) DecryptPacked(ct GLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptGLWE(ct))
}

// DecryptGLWE decrypts a GLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	pt := GLWEPlaintext[T]{Value: ct.Body.Copy()}
	e.DecryptGLWEInPlace(ct, pt)
	return pt
}

// DecryptGLWEInPlace decrypts ct and saves it to pt.
func (e Encrypter[T]) DecryptGLWEInPlace(ct GLWECiphertext[T], pt GLWEPlaintext[T]) {
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluator.MulSubAssign(ct.Mask[i], e.glweKey.Value[i], pt.Value)
	}
}

// DecryptGLevInPlace decrypts leveled GLWE ciphertexts to GLWE plaintext.
//
// Panics if decompParams is invalid, or input GLev is inconsistent with decompParams.
func (e Encrypter[T]) DecryptGLevInPlace(ct []GLWECiphertext[T], decompParams DecompositionParameters[T], pt GLWEPlaintext[T]) {
	glweCt := ct[decompParams.level-1] // Pick the last level
	e.DecryptGLWEInPlace(glweCt, pt)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		pt.Value.Coeffs[i] = num.RoundRatioBits(pt.Value.Coeffs[i], decompParams.maxBits-decompParams.level*decompParams.baseLog)
	}
}

// EncryptGSWInPlace encrypts LWE plaintext to GSW ciphertexts, according to decompParams.
//
// Panics if decompParams is invalid.
func (e Encrypter[T]) EncryptGSWInPlace(pt LWEPlaintext[T], decompParams DecompositionParameters[T], ct GSWCiphertext[T]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		if i < e.Parameters.lweDimension { // -Si * Pt
			e.EncryptLevInPlace(LWEPlaintext[T]{Value: -e.lweKey.Value[i] * pt.Value}, decompParams, ct.Value[i])
		} else { // Pt
			e.EncryptLevInPlace(pt, decompParams, ct.Value[i])
		}
	}
}

// DecryptGSW decrypts a GSW ciphertext to messages.
func (e Encrypter[T]) DecryptGSW(ct GSWCiphertext[T]) LWEPlaintext[T] {
	return e.DecryptLev(ct.ToLev(), ct.decompParams)
}

// EncryptGGSW encrypts GLWE plaintext to GGSW ciphertext and returns it, according to decompParams.
//
// Panics if decompParams is invalid.
func (e Encrypter[T]) EncryptGGSW(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	ct := NewGGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGGSWInPlace(pt, decompParams, ct)
	return ct
}

// EncryptGGSWInPlace encrypts GLWE plaintext to GGSW ciphertext, according to decompParams.
//
// Panics if decompParams is invalid.
func (e Encrypter[T]) EncryptGGSWInPlace(pt GLWEPlaintext[T], decompParams DecompositionParameters[T], ct GGSWCiphertext[T]) {
	ct.decompParams = decompParams
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		if i < e.Parameters.glweDimension { // -Si * Pt
			e.polyEvaluator.MulInPlace(pt.Value, e.glweKey.Value[i], e.buffGLWEPlaintext)
			e.polyEvaluator.NegAssign(e.buffGLWEPlaintext)
		} else { // Pt
			e.buffGLWEPlaintext.CopyFrom(pt.Value)
		}
		e.EncryptGLevInPlace(GLWEPlaintext[T]{Value: e.buffGLWEPlaintext}, decompParams, ct.Value[i])
	}
}

// DecryptGGSW decrypts a GGSW ciphertext to GLWE plaintext and returns it.
func (e Encrypter[T]) DecryptGGSW(ct GGSWCiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLevInPlace(ct.ToGLev(), ct.decompParams, pt)
	return pt
}

// DecryptGGSWInPlace decrypts a GGSW ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGGSWInPlace(ct GGSWCiphertext[T], pt GLWEPlaintext[T]) {
	e.DecryptGLevInPlace(ct.ToGLev(), ct.decompParams, pt)
}

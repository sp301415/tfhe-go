package tfhe

import (
	"math"
	"runtime"
	"sync"

	"github.com/sp301415/tfhe/math/num"
)

// SecretKey is a struct consisted of LWE key and GLWE key.
type SecretKey[T Tint] struct {
	LWEKey  LWEKey[T]
	GLWEKey GLWEKey[T]
}

// GenSecretKey samples a new LWE and GLWE key.
func (e Encrypter[T]) GenSecretKey() SecretKey[T] {
	lsk := NewLWEKey(e.Parameters)
	gsk := NewGLWEKey(e.Parameters)

	e.binarySampler.SampleSliceAssign(lsk.Value)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.binarySampler.SamplePolyAssign(gsk.Value[i])
	}

	return SecretKey[T]{
		LWEKey:  lsk,
		GLWEKey: gsk,
	}
}

// SetSecretKey sets the secret key of Encrypter to sk.
// This does not copy values.
func (e *Encrypter[T]) SetSecretKey(sk SecretKey[T]) {
	e.lweKey = sk.LWEKey
	e.glweKey = sk.GLWEKey
	e.lweLargeKey = sk.GLWEKey.ToLWEKey()
}

// SecretKey returns the secret key of Encrypter.
// This does not copy values.
func (e Encrypter[T]) SecretKey() SecretKey[T] {
	return SecretKey[T]{
		LWEKey:  e.lweKey,
		GLWEKey: e.glweKey,
	}
}

// GenEvaluationKey samples a new evaluation key for bootstrapping.
// This may take a long time, depending on the parameters.
// Consider using GenEvaluationKeyParallel.
func (e Encrypter[T]) GenEvaluationKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: e.GenBootstrapKey(),
		KeySwitchKey: e.GenKeySwitchKeyForBootstrap(),
	}
}

// GenEvaluationKey samples a new evaluation key for bootstrapping in parallel.
func (e Encrypter[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: e.GenBootstrapKeyParallel(),
		KeySwitchKey: e.GenKeySwitchKeyForBootstrapParallel(),
	}
}

// GenBootstrapKey samples a new bootstrapping key.
// This may take a long time, depending on the parameters.
// Consider using GenBootstrappingKeyParallel.
func (e Encrypter[T]) GenBootstrapKey() BootstrapKey[T] {
	bsk := NewBootstrapKey(e.Parameters)

	e.buffer.glwePtForPBSKeyGen.Value.Clear()
	for i := 0; i < e.Parameters.lweDimension; i++ {
		e.buffer.glwePtForPBSKeyGen.Value.Coeffs[0] = e.lweKey.Value[i]
		e.EncryptFourierGGSWInPlace(e.buffer.glwePtForPBSKeyGen, bsk.Value[i])
	}
	return bsk
}

// GenBootstrapKeyParallel samples a new bootstrapping key in parallel.
func (e Encrypter[T]) GenBootstrapKeyParallel() BootstrapKey[T] {
	bsk := NewBootstrapKey(e.Parameters)

	// LWEDimension is usually 500 ~ 1000,
	// and GLWEDimension is usually 1 ~ 5.
	// so we chunk it between min of NumCPU and sqrt(LWEDimension * (GLWEDimension + 1)).
	workSize := e.Parameters.lweDimension * (e.Parameters.glweDimension + 1)
	chunkCount := num.Min(runtime.NumCPU(), int(math.Sqrt(float64(workSize))))

	encrypters := make([]Encrypter[T], chunkCount)
	for i := 0; i < chunkCount; i++ {
		encrypters[i] = e.ShallowCopy()
	}

	ch := make(chan [2]int) // i, j
	go func() {
		defer close(ch)
		for i := 0; i < e.Parameters.lweDimension; i++ {
			for j := 0; j < e.Parameters.glweDimension+1; j++ {
				ch <- [2]int{i, j}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(chunkIdx int) {
			defer wg.Done()
			for ij := range ch {
				encrypters[chunkIdx].genBootstrapKeyIndex(ij[0], ij[1], bsk)
			}
		}(i)
	}
	wg.Wait()

	return bsk
}

// genBootstrapKeyIndex samples one index of bootstrapping key: GGSW(LWEKey_i)_j,
// where 0 <= i < LWEDimension and 0 <= j < GLWEDimension + 1.
// This is the minimum workload that can be executed in parallel, and we abuse the fact that
// bootstrapping key only encrypts scalar values.
func (e Encrypter[T]) genBootstrapKeyIndex(i, j int, bsk BootstrapKey[T]) {
	if j == 0 {
		e.buffer.glwePtForPBSKeyGen.Value.Clear()
		e.buffer.glwePtForPBSKeyGen.Value.Coeffs[0] = e.lweKey.Value[i]
	} else {
		e.PolyEvaluater.ScalarMulInPlace(e.glweKey.Value[j-1], -e.lweKey.Value[i], e.buffer.glwePtForPBSKeyGen.Value)
	}
	e.EncryptFourierGLevInPlace(e.buffer.glwePtForPBSKeyGen, bsk.Value[i].Value[j])
}

// GenKeySwitchKey samples a new keyswitching key skIn -> e.LWEKey.
// This may take a long time, depending on the parameters.
// Consider using GenKeySwitchingKeyParallel.
func (e Encrypter[T]) GenKeySwitchKey(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchKey[T] {
	ksk := NewKeySwitchKey(len(skIn.Value), len(e.lweKey.Value), decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.EncryptLevInPlace(LWEPlaintext[T]{Value: skIn.Value[i]}, ksk.Value[i])
	}

	return ksk
}

// GenKeySwitchKeyParallel samples a new keyswitching key skIn -> e.LWEKey in parallel.
func (e Encrypter[T]) GenKeySwitchKeyParallel(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchKey[T] {
	ksk := NewKeySwitchKey(len(skIn.Value), len(e.lweKey.Value), decompParams)

	// LWEDimension is usually 500 ~ 1000,
	// so we chunk it between min of NumCPU and sqrt(InputLWEDimension).
	chunkCount := num.Min(runtime.NumCPU(), int(math.Sqrt(float64(ksk.InputLWEDimension()))))

	encrypters := make([]Encrypter[T], chunkCount)
	for i := 0; i < chunkCount; i++ {
		encrypters[i] = e.ShallowCopy()
	}

	ch := make(chan int)
	go func() {
		defer close(ch)
		for i := 0; i < ksk.InputLWEDimension(); i++ {
			ch <- i
		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(chunkIdx int) {
			defer wg.Done()
			for i := range ch {
				encrypters[chunkIdx].EncryptLevInPlace(LWEPlaintext[T]{Value: skIn.Value[i]}, ksk.Value[i])
			}
		}(i)
	}
	wg.Wait()

	return ksk
}

// GenKeySwitchKeyForBootstrap samples a new keyswitching key LWELargeKey -> LWEKey,
// used for bootstrapping.
// This may take a long time, depending on the parameters.
// Consider using GenKeySwitchingKeyForBootstrappingParallel.
func (e Encrypter[T]) GenKeySwitchKeyForBootstrap() KeySwitchKey[T] {
	return e.GenKeySwitchKey(e.lweLargeKey, e.Parameters.keyswitchParameters)
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitching key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e Encrypter[T]) GenKeySwitchKeyForBootstrapParallel() KeySwitchKey[T] {
	return e.GenKeySwitchKeyParallel(e.lweLargeKey, e.Parameters.keyswitchParameters)
}

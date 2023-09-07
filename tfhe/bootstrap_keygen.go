package tfhe

import (
	"runtime"
	"sync"

	"github.com/sp301415/tfhe/math/num"
)

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use GenEvaluationKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenEvaluationKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: e.GenBootstrapKey(),
		KeySwitchKey: e.GenKeySwitchKeyForBootstrap(),
	}
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *Encryptor[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: e.GenBootstrapKeyParallel(),
		KeySwitchKey: e.GenKeySwitchKeyForBootstrapParallel(),
	}
}

// GenBootstrapKey samples a new bootstrapping key.
//
// This can take a long time.
// Use GenBootstrapKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenBootstrapKey() BootstrapKey[T] {
	bsk := NewBootstrapKey(e.Parameters)

	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			if j == 0 {
				e.buffer.ptGGSW.Clear()
				e.buffer.ptGGSW.Coeffs[0] = e.SecretKey.LWEKey.Value[i]
			} else {
				e.PolyEvaluator.ScalarMulAssign(e.SecretKey.GLWEKey.Value[j-1], e.SecretKey.LWEKey.Value[i], e.buffer.ptGGSW)
			}
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.PolyEvaluator.ScalarMulAssign(e.buffer.ptGGSW, e.Parameters.bootstrapParameters.ScaledBase(k), e.buffer.ctGLWE.Value[0])
				e.EncryptGLWEBody(e.buffer.ctGLWE)
				e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, bsk.Value[i].Value[j].Value[k])
			}
		}
	}

	return bsk
}

// GenBootstrapKeyParallel samples a new bootstrapping key in parallel.
func (e *Encryptor[T]) GenBootstrapKeyParallel() BootstrapKey[T] {
	bsk := NewBootstrapKey(e.Parameters)

	workSize := e.Parameters.lweDimension * (e.Parameters.glweDimension + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < e.Parameters.lweDimension; i++ {
			for j := 0; j < e.Parameters.glweDimension+1; j++ {
				jobs <- [2]int{i, j}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(chunkIdx int) {
			defer wg.Done()
			e := encryptorPool[chunkIdx]

			for job := range jobs {
				i, j := job[0], job[1]

				if j == 0 {
					e.buffer.ptGGSW.Clear()
					e.buffer.ptGGSW.Coeffs[0] = e.SecretKey.LWEKey.Value[i]
				} else {
					e.PolyEvaluator.ScalarMulAssign(e.SecretKey.GLWEKey.Value[j-1], e.SecretKey.LWEKey.Value[i], e.buffer.ptGGSW)
				}
				for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
					e.PolyEvaluator.ScalarMulAssign(e.buffer.ptGGSW, e.Parameters.bootstrapParameters.ScaledBase(k), e.buffer.ctGLWE.Value[0])
					e.EncryptGLWEBody(e.buffer.ctGLWE)
					e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, bsk.Value[i].Value[j].Value[k])
				}
			}
		}(i)
	}
	wg.Wait()

	return bsk
}

// GenKeySwitchKey samples a new keyswitch key skIn -> e.SecretKey.LWEKey.
//
// This can take a long time.
// Use GenKeySwitchKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenKeySwitchKey(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchKey[T] {
	ksk := NewKeySwitchKey(len(skIn.Value), len(e.SecretKey.LWEKey.Value), decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		for j := 0; j < decompParams.level; j++ {
			ksk.Value[i].Value[j].Value[0] = skIn.Value[i] << decompParams.ScaledBaseLog(j)
			e.EncryptLWEBody(ksk.Value[i].Value[j])
		}
	}

	return ksk
}

// GenKeySwitchKeyParallel samples a new keyswitch key skIn -> e.SecretKey.LWEKey in parallel.
func (e *Encryptor[T]) GenKeySwitchKeyParallel(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchKey[T] {
	ksk := NewKeySwitchKey(len(skIn.Value), len(e.SecretKey.LWEKey.Value), decompParams)

	workSize := ksk.InputLWEDimension() * decompParams.level
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < ksk.InputLWEDimension(); i++ {
			for j := 0; j < decompParams.level; j++ {
				jobs <- [2]int{i, j}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(chunkIdx int) {
			defer wg.Done()
			e := encryptorPool[chunkIdx]

			for jobs := range jobs {
				i, j := jobs[0], jobs[1]
				ksk.Value[i].Value[j].Value[0] = skIn.Value[i] << decompParams.ScaledBaseLog(j)
				e.EncryptLWEBody(ksk.Value[i].Value[j])
			}
		}(i)
	}
	wg.Wait()

	return ksk
}

// GenKeySwitchKeyForBootstrap samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use GenKeySwitchKeyForBootstrapParallel for better key generation performance.
func (e *Encryptor[T]) GenKeySwitchKeyForBootstrap() KeySwitchKey[T] {
	skIn := LWEKey[T]{Value: e.SecretKey.LWELargeKey.Value[e.Parameters.lweDimension:]}
	return e.GenKeySwitchKey(skIn, e.Parameters.keyswitchParameters)
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *Encryptor[T]) GenKeySwitchKeyForBootstrapParallel() KeySwitchKey[T] {
	skIn := LWEKey[T]{Value: e.SecretKey.LWELargeKey.Value[e.Parameters.lweDimension:]}
	return e.GenKeySwitchKeyParallel(skIn, e.Parameters.keyswitchParameters)
}

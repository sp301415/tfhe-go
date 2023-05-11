package tfhe

import (
	"math"
	"runtime"
	"sync"

	"github.com/sp301415/tfhe/math/num"
)

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

// GenEvaluationKey samples a new evaluation key for bootstrapping.
// This may take a long time, depending on the parameters.
// Consider using GenEvaluationKeyParallel.
func (e Encrypter[T]) GenEvaluationKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrappingKey: e.GenBootstrappingKey(),
		KeySwitchingKey:  e.GenKeySwitchingKeyForBootstrapping(),
	}
}

// GenEvaluationKey samples a new evaluation key for bootstrapping in parallel.
func (e Encrypter[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	var bsk BootstrappingKey[T]
	var ksk KeySwitchingKey[T]

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bsk = e.GenBootstrappingKeyParallel()
	}()
	go func() {
		defer wg.Done()
		ksk = e.GenKeySwitchingKeyForBootstrappingParallel()
	}()

	wg.Wait()

	return EvaluationKey[T]{
		BootstrappingKey: bsk,
		KeySwitchingKey:  ksk,
	}
}

// GenBootstrappingKey samples a new bootstrapping key.
// This may take a long time, depending on the parameters.
// Consider using GenBootstrappingKeyParallel.
func (e Encrypter[T]) GenBootstrappingKey() BootstrappingKey[T] {
	bsk := NewBootstrappingKey(e.Parameters, e.Parameters.pbsParameters)
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.genBootstrappingKeyIndex(i, j, bsk)
		}
	}
	return bsk
}

// GenBootstrappingKeyParallel samples a new bootstrapping key in parallel.
func (e Encrypter[T]) GenBootstrappingKeyParallel() BootstrappingKey[T] {
	bsk := NewBootstrappingKey(e.Parameters, e.Parameters.pbsParameters)

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
				encrypters[chunkIdx].genBootstrappingKeyIndex(ij[0], ij[1], bsk)
			}
		}(i)
	}
	wg.Wait()

	return bsk
}

// genBootstrappingKeyIndex samples one index of bootstrapping key: GGSW(LWEKey_i)_j,
// where 0 <= i < LWEDimension and 0 <= j < GLWEDimension + 1
// This is the minimum workload that can be executed in parallel.
func (e Encrypter[T]) genBootstrappingKeyIndex(i, j int, bsk BootstrappingKey[T]) {
	if j == 0 {
		for k := 0; k < e.Parameters.pbsParameters.level; k++ {
			e.buffer.GLWEPtForPBSKeyGen.Value.Clear()
			e.buffer.GLWEPtForPBSKeyGen.Value.Coeffs[0] = e.lweKey.Value[i] << e.Parameters.pbsParameters.ScaledBaseLog(k)
			e.EncryptGLWEInPlace(e.buffer.GLWEPtForPBSKeyGen, e.buffer.GLWECtForPBSKeyGen)
			for l := 0; l < e.Parameters.glweDimension+1; l++ {
				e.FourierTransformer.ToFourierPolyInPlace(e.buffer.GLWECtForPBSKeyGen.Value[l], bsk.Value[i][j][k].Value[l])
			}
		}
	} else {
		for k := 0; k < e.Parameters.pbsParameters.level; k++ {
			p := -(e.lweKey.Value[i] << e.Parameters.pbsParameters.ScaledBaseLog(k))
			e.PolyEvaluater.ScalarMulInPlace(e.glweKey.Value[j-1], p, e.buffer.GLWEPtForPBSKeyGen.Value)
			e.EncryptGLWEInPlace(e.buffer.GLWEPtForPBSKeyGen, e.buffer.GLWECtForPBSKeyGen)
			for l := 0; l < e.Parameters.glweDimension+1; l++ {
				e.FourierTransformer.ToFourierPolyInPlace(e.buffer.GLWECtForPBSKeyGen.Value[l], bsk.Value[i][j][k].Value[l])
			}
		}
	}

}

// GenKeySwitchingKey samples a new keyswitching key skIn -> e.LWEKey.
// This may take a long time, depending on the parameters.
// Consider using GenKeySwitchingKeyParallel.
func (e Encrypter[T]) GenKeySwitchingKey(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchingKey[T] {
	ksk := NewKeySwitchingKey(len(skIn.Value), len(e.lweKey.Value), decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.EncryptLevInPlace(LWEPlaintext[T]{Value: skIn.Value[i]}, ksk.Value[i])
	}

	return ksk
}

// GenKeySwitchingKeyParallel samples a new keyswitching key skIn -> e.LWEKey in parallel.
func (e Encrypter[T]) GenKeySwitchingKeyParallel(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchingKey[T] {
	ksk := NewKeySwitchingKey(len(skIn.Value), len(e.lweKey.Value), decompParams)

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

// GenKeySwitchingKeyForBootstrapping samples a new keyswitching key LWELargeKey -> LWEKey,
// used for bootstrapping.
// This may take a long time, depending on the parameters.
// Consider using GenKeySwitchingKeyForBootstrappingParallel.
func (e Encrypter[T]) GenKeySwitchingKeyForBootstrapping() KeySwitchingKey[T] {
	return e.GenKeySwitchingKey(e.lweLargeKey, e.Parameters.keyswitchParameters)
}

// GenKeySwitchingKeyForBootstrappingParallel samples a new keyswitching key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e Encrypter[T]) GenKeySwitchingKeyForBootstrappingParallel() KeySwitchingKey[T] {
	return e.GenKeySwitchingKeyParallel(e.lweLargeKey, e.Parameters.keyswitchParameters)
}

package tfhe

import (
	"runtime"
	"sync"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenEvaluationKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenEvaluationKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		BlindRotateKey: e.GenBlindRotateKey(),
		KeySwitchKey:   e.GenDefaultKeySwitchKey(),
	}
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *Encryptor[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	return EvaluationKey[T]{
		BlindRotateKey: e.GenBlindRotateKeyParallel(),
		KeySwitchKey:   e.GenDefaultKeySwitchKeyParallel(),
	}
}

// GenBlindRotateKey samples a new bootstrapping key.
//
// This can take a long time.
// Use [*Encryptor.GenBlindRotateKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenBlindRotateKey() BlindRotateKey[T] {
	brk := NewBlindRotateKey(e.Params)

	for i := 0; i < e.Params.lweDimension; i++ {
		for j := 0; j < e.Params.glweRank+1; j++ {
			if j == 0 {
				e.buf.ptGGSW.Clear()
				e.buf.ptGGSW.Coeffs[0] = e.SecretKey.LWEKey.Value[i]
			} else {
				e.PolyEvaluator.ScalarMulPolyTo(e.buf.ptGGSW, e.SecretKey.GLWEKey.Value[j-1], e.SecretKey.LWEKey.Value[i])
			}
			for k := 0; k < e.Params.blindRotateParams.level; k++ {
				e.PolyEvaluator.ScalarMulPolyTo(e.buf.ctGLWE.Value[0], e.buf.ptGGSW, e.Params.blindRotateParams.BaseQ(k))
				e.EncryptGLWEBody(e.buf.ctGLWE)
				e.FFTGLWECiphertextTo(brk.Value[i].Value[j].Value[k], e.buf.ctGLWE)
			}
		}
	}

	return brk
}

// GenBlindRotateKeyParallel samples a new bootstrapping key in parallel.
func (e *Encryptor[T]) GenBlindRotateKeyParallel() BlindRotateKey[T] {
	brk := NewBlindRotateKey(e.Params)

	workSize := e.Params.lweDimension * (e.Params.glweRank + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.SafeCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < e.Params.lweDimension; i++ {
			for j := 0; j < e.Params.glweRank+1; j++ {
				jobs <- [2]int{i, j}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(i int) {
			eIdx := encryptorPool[i]
			for job := range jobs {
				i, j := job[0], job[1]

				if j == 0 {
					eIdx.buf.ptGGSW.Clear()
					eIdx.buf.ptGGSW.Coeffs[0] = eIdx.SecretKey.LWEKey.Value[i]
				} else {
					eIdx.PolyEvaluator.ScalarMulPolyTo(eIdx.buf.ptGGSW, eIdx.SecretKey.GLWEKey.Value[j-1], eIdx.SecretKey.LWEKey.Value[i])
				}
				for k := 0; k < eIdx.Params.blindRotateParams.level; k++ {
					eIdx.PolyEvaluator.ScalarMulPolyTo(eIdx.buf.ctGLWE.Value[0], eIdx.buf.ptGGSW, eIdx.Params.blindRotateParams.BaseQ(k))
					eIdx.EncryptGLWEBody(eIdx.buf.ctGLWE)
					eIdx.FFTGLWECiphertextTo(brk.Value[i].Value[j].Value[k], eIdx.buf.ctGLWE)
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	return brk
}

// GenDefaultKeySwitchKey samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenDefaultKeySwitchKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenDefaultKeySwitchKey() LWEKeySwitchKey[T] {
	skIn := LWESecretKey[T]{Value: e.SecretKey.LWELargeKey.Value[e.Params.lweDimension:]}
	ksk := NewKeySwitchKeyForBootstrap(e.Params)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		for j := 0; j < e.Params.keySwitchParams.level; j++ {
			ksk.Value[i].Value[j].Value[0] = skIn.Value[i] << e.Params.keySwitchParams.LogBaseQ(j)

			e.UniformSampler.SampleVecTo(ksk.Value[i].Value[j].Value[1:])
			ksk.Value[i].Value[j].Value[0] += -vec.Dot(ksk.Value[i].Value[j].Value[1:], e.SecretKey.LWEKey.Value)
			ksk.Value[i].Value[j].Value[0] += e.GaussianSampler.Sample(e.Params.LWEStdDevQ())
		}
	}

	return ksk
}

// GenDefaultKeySwitchKeyParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *Encryptor[T]) GenDefaultKeySwitchKeyParallel() LWEKeySwitchKey[T] {
	skIn := LWESecretKey[T]{Value: e.SecretKey.LWELargeKey.Value[e.Params.lweDimension:]}
	ksk := NewKeySwitchKeyForBootstrap(e.Params)

	workSize := ksk.InputLWEDimension() * e.Params.keySwitchParams.level
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.SafeCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < ksk.InputLWEDimension(); i++ {
			for j := 0; j < e.Params.keySwitchParams.level; j++ {
				jobs <- [2]int{i, j}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(i int) {
			eIdx := encryptorPool[i]
			for jobs := range jobs {
				i, j := jobs[0], jobs[1]
				ksk.Value[i].Value[j].Value[0] = skIn.Value[i] << eIdx.Params.keySwitchParams.LogBaseQ(j)
				eIdx.UniformSampler.SampleVecTo(ksk.Value[i].Value[j].Value[1:])
				ksk.Value[i].Value[j].Value[0] += -vec.Dot(ksk.Value[i].Value[j].Value[1:], eIdx.SecretKey.LWEKey.Value)
				ksk.Value[i].Value[j].Value[0] += eIdx.GaussianSampler.Sample(eIdx.Params.LWEStdDevQ())
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	return ksk
}

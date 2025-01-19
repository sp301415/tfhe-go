package xtfhe

import (
	"runtime"
	"sync"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// EvaluationKey is a public key for FHEW Evaluator.
type FHEWEvaluationKey[T tfhe.TorusInt] struct {
	// BlindRotateKey is the key for blind rotation.
	BlindRotateKey tfhe.BlindRotateKey[T]
	// KeySwitchKey is the key for key switching.
	KeySwitchKey tfhe.LWEKeySwitchKey[T]
	// GaloisKey is the key for Galois automorphisms.
	// GaloisKey has length WindowSize + 1,
	// where the first element is key for X -> X^-5,
	// and the next WindowSize elements are keys for X -> X^5^i.
	GaloisKey []tfhe.GLWEKeySwitchKey[T]
}

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*FHEWEncryptor.GenEvaluationKeyParallel] for better key generation performance.
func (e *FHEWEncryptor[T]) GenEvaluationKey() FHEWEvaluationKey[T] {
	return FHEWEvaluationKey[T]{
		BlindRotateKey: e.GenBlindRotateKey(),
		KeySwitchKey:   e.GenKeySwitchKeyForBootstrap(),
		GaloisKey:      e.GenGaloisKey(),
	}
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *FHEWEncryptor[T]) GenEvaluationKeyParallel() FHEWEvaluationKey[T] {
	return FHEWEvaluationKey[T]{
		BlindRotateKey: e.GenBlindRotateKeyParallel(),
		KeySwitchKey:   e.GenKeySwitchKeyForBootstrapParallel(),
		GaloisKey:      e.GenGaloisKey(),
	}
}

// GenBlindRotateKey samples a new bootstrapping key.
//
// This can take a long time.
// Use [*FHEWEncryptor.GenBlindRotateKeyParallel] for better key generation performance.
func (e *FHEWEncryptor[T]) GenBlindRotateKey() tfhe.BlindRotateKey[T] {
	brk := tfhe.NewBlindRotateKey(e.Parameters.baseParameters)

	for i := 0; i < e.Parameters.baseParameters.LWEDimension(); i++ {
		var sMonoIdx int

		var z T
		switch any(z).(type) {
		case uint32:
			sMonoIdx = int(int32(e.SecretKey.LWEKey.Value[i]))
		case uint64:
			sMonoIdx = int(int64(e.SecretKey.LWEKey.Value[i]))
		}

		for j := 0; j < e.Parameters.baseParameters.GLWERank()+1; j++ {
			if j == 0 {
				e.buffer.ptGGSW.Clear()
				e.buffer.ptGGSW.Coeffs[0] = 1
				e.PolyEvaluator.MonomialMulPolyInPlace(e.buffer.ptGGSW, sMonoIdx)
			} else {
				e.PolyEvaluator.MonomialMulPolyAssign(e.SecretKey.GLWEKey.Value[j-1], sMonoIdx, e.buffer.ptGGSW)
			}
			for k := 0; k < e.Parameters.baseParameters.BlindRotateParameters().Level(); k++ {
				e.PolyEvaluator.ScalarMulPolyAssign(e.buffer.ptGGSW, e.Parameters.baseParameters.BlindRotateParameters().BaseQ(k), e.buffer.ctGLWE.Value[0])
				e.EncryptGLWEBody(e.buffer.ctGLWE)
				e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, brk.Value[i].Value[j].Value[k])
			}
		}
	}

	return brk
}

// GenBlindRotateKeyParallel samples a new bootstrapping key in parallel.
func (e *FHEWEncryptor[T]) GenBlindRotateKeyParallel() tfhe.BlindRotateKey[T] {
	brk := tfhe.NewBlindRotateKey(e.Parameters.baseParameters)

	workSize := e.Parameters.baseParameters.LWEDimension() * (e.Parameters.baseParameters.GLWERank() + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*FHEWEncryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < e.Parameters.baseParameters.LWEDimension(); i++ {
			for j := 0; j < e.Parameters.baseParameters.GLWERank()+1; j++ {
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

				var sMonoIdx int

				var z T
				switch any(z).(type) {
				case uint32:
					sMonoIdx = int(int32(eIdx.SecretKey.LWEKey.Value[i]))
				case uint64:
					sMonoIdx = int(int64(eIdx.SecretKey.LWEKey.Value[i]))
				}

				if j == 0 {
					eIdx.buffer.ptGGSW.Clear()
					eIdx.buffer.ptGGSW.Coeffs[0] = 1
					eIdx.PolyEvaluator.MonomialMulPolyInPlace(eIdx.buffer.ptGGSW, sMonoIdx)
				} else {
					eIdx.PolyEvaluator.MonomialMulPolyAssign(eIdx.SecretKey.GLWEKey.Value[j-1], sMonoIdx, eIdx.buffer.ptGGSW)
				}
				for k := 0; k < eIdx.Parameters.baseParameters.BlindRotateParameters().Level(); k++ {
					eIdx.PolyEvaluator.ScalarMulPolyAssign(eIdx.buffer.ptGGSW, eIdx.Parameters.baseParameters.BlindRotateParameters().BaseQ(k), eIdx.buffer.ctGLWE.Value[0])
					eIdx.EncryptGLWEBody(eIdx.buffer.ctGLWE)
					eIdx.ToFourierGLWECiphertextAssign(eIdx.buffer.ctGLWE, brk.Value[i].Value[j].Value[k])
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	return brk
}

// GenGaloisKey samples a new Galois key for bootstrapping.
func (e *FHEWEncryptor[T]) GenGaloisKey() []tfhe.GLWEKeySwitchKey[T] {
	glk := make([]tfhe.GLWEKeySwitchKey[T], e.Parameters.windowSize+1)

	for j := 0; j < e.Parameters.baseParameters.GLWERank(); j++ {
		e.PolyEvaluator.PermutePolyAssign(e.SecretKey.GLWEKey.Value[j], -5, e.buffer.skPermute.Value[j])
	}
	glk[0] = e.GenGLWEKeySwitchKey(e.buffer.skPermute, e.Parameters.baseParameters.BlindRotateParameters())

	for i := 1; i < e.Parameters.windowSize+1; i++ {
		d := num.ModExp(5, i, 2*e.Parameters.baseParameters.PolyDegree())
		for j := 0; j < e.Parameters.baseParameters.GLWERank(); j++ {
			e.PolyEvaluator.PermutePolyAssign(e.SecretKey.GLWEKey.Value[j], d, e.buffer.skPermute.Value[j])
		}
		glk[i] = e.GenGLWEKeySwitchKey(e.buffer.skPermute, e.Parameters.baseParameters.BlindRotateParameters())
	}

	return glk
}

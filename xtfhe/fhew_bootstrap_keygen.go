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

// GenEvalKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*FHEWEncryptor.GenEvalKeyParallel] for better key generation performance.
func (e *FHEWEncryptor[T]) GenEvalKey() FHEWEvaluationKey[T] {
	return FHEWEvaluationKey[T]{
		BlindRotateKey: e.GenBlindRotateKey(),
		KeySwitchKey:   e.GenDefaultKeySwitchKey(),
		GaloisKey:      e.GenGaloisKey(),
	}
}

// GenEvalKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *FHEWEncryptor[T]) GenEvalKeyParallel() FHEWEvaluationKey[T] {
	return FHEWEvaluationKey[T]{
		BlindRotateKey: e.GenBlindRotateKeyParallel(),
		KeySwitchKey:   e.GenDefaultKeySwitchKeyParallel(),
		GaloisKey:      e.GenGaloisKey(),
	}
}

// GenBlindRotateKey samples a new bootstrapping key.
//
// This can take a long time.
// Use [*FHEWEncryptor.GenBlindRotateKeyParallel] for better key generation performance.
func (e *FHEWEncryptor[T]) GenBlindRotateKey() tfhe.BlindRotateKey[T] {
	brk := tfhe.NewBlindRotateKey(e.Params.baseParams)

	for i := 0; i < e.Params.baseParams.LWEDimension(); i++ {
		var sMonoIdx int

		var z T
		switch any(z).(type) {
		case uint32:
			sMonoIdx = int(int32(e.SecretKey.LWEKey.Value[i]))
		case uint64:
			sMonoIdx = int(int64(e.SecretKey.LWEKey.Value[i]))
		}

		for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
			if j == 0 {
				e.buf.ptGGSW.Clear()
				e.buf.ptGGSW.Coeffs[0] = 1
				e.PolyEvaluator.MonomialMulPolyInPlace(e.buf.ptGGSW, sMonoIdx)
			} else {
				e.PolyEvaluator.MonomialMulPolyTo(e.buf.ptGGSW, e.SecretKey.GLWEKey.Value[j-1], sMonoIdx)
			}
			for k := 0; k < e.Params.baseParams.BlindRotateParams().Level(); k++ {
				e.PolyEvaluator.ScalarMulPolyTo(e.buf.ctGLWE.Value[0], e.buf.ptGGSW, e.Params.baseParams.BlindRotateParams().BaseQ(k))
				e.EncryptGLWEBody(e.buf.ctGLWE)
				e.FwdFFTGLWECiphertextTo(brk.Value[i].Value[j].Value[k], e.buf.ctGLWE)
			}
		}
	}

	return brk
}

// GenBlindRotateKeyParallel samples a new bootstrapping key in parallel.
func (e *FHEWEncryptor[T]) GenBlindRotateKeyParallel() tfhe.BlindRotateKey[T] {
	brk := tfhe.NewBlindRotateKey(e.Params.baseParams)

	workSize := e.Params.baseParams.LWEDimension() * (e.Params.baseParams.GLWERank() + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*FHEWEncryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.SafeCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < e.Params.baseParams.LWEDimension(); i++ {
			for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
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
					eIdx.buf.ptGGSW.Clear()
					eIdx.buf.ptGGSW.Coeffs[0] = 1
					eIdx.PolyEvaluator.MonomialMulPolyInPlace(eIdx.buf.ptGGSW, sMonoIdx)
				} else {
					eIdx.PolyEvaluator.MonomialMulPolyTo(eIdx.buf.ptGGSW, eIdx.SecretKey.GLWEKey.Value[j-1], sMonoIdx)
				}
				for k := 0; k < eIdx.Params.baseParams.BlindRotateParams().Level(); k++ {
					eIdx.PolyEvaluator.ScalarMulPolyTo(eIdx.buf.ctGLWE.Value[0], eIdx.buf.ptGGSW, eIdx.Params.baseParams.BlindRotateParams().BaseQ(k))
					eIdx.EncryptGLWEBody(eIdx.buf.ctGLWE)
					eIdx.FwdFFTGLWECiphertextTo(brk.Value[i].Value[j].Value[k], eIdx.buf.ctGLWE)
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
	glk := make([]tfhe.GLWEKeySwitchKey[T], e.Params.windowSize+1)

	for j := 0; j < e.Params.baseParams.GLWERank(); j++ {
		e.PolyEvaluator.PermutePolyTo(e.buf.skPermute.Value[j], e.SecretKey.GLWEKey.Value[j], -5)
	}
	glk[0] = e.GenGLWEKeySwitchKey(e.buf.skPermute, e.Params.baseParams.BlindRotateParams())

	for i := 1; i < e.Params.windowSize+1; i++ {
		d := num.ModExp(5, i, 2*e.Params.baseParams.PolyRank())
		for j := 0; j < e.Params.baseParams.GLWERank(); j++ {
			e.PolyEvaluator.PermutePolyTo(e.buf.skPermute.Value[j], e.SecretKey.GLWEKey.Value[j], d)
		}
		glk[i] = e.GenGLWEKeySwitchKey(e.buf.skPermute, e.Params.baseParams.BlindRotateParams())
	}

	return glk
}

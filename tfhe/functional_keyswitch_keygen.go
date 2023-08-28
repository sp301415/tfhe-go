package tfhe

import (
	"runtime"
	"sync"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// GenPrivateFunctionalLWEKeySwitchKey samples a new private functional keyswitch key
// for LWE private keyswitching.
//
// The function f has the form f(in []T) T,
// where length of in is always inputCount.
//
// This can take a long time.
// Use GenPrivateFunctionalLWEKeySwitchKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenPrivateFunctionalLWEKeySwitchKey(inputCount int, f func([]T) T, decompParams DecompositionParameters[T]) PrivateFunctionalLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	in := make([]T, inputCount)
	for i := 0; i < inputCount; i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			for k := 0; k < decompParams.level; k++ {
				if j == 0 {
					in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
				} else {
					in[i] = e.SecretKey.LWEKey.Value[j-1] << decompParams.ScaledBaseLog(k)
				}
				pfksk.Value[i].Value[j].Value[k].Value[0] = f(in)
				e.EncryptLWEBody(pfksk.Value[i].Value[j].Value[k])
			}
		}
		in[i] = 0
	}

	return pfksk
}

// GenPrivateFunctionalLWEKeySwitchKeyParallel samples a new private functional keyswitch key
// for LWE private keyswitching in parallel.
//
// The function f has the form f(in []T) T,
// where length of in is always inputCount.
// f should also be thread-safe.
func (e *Encryptor[T]) GenPrivateFunctionalLWEKeySwitchKeyParallel(inputCount int, f func([]T) T, decompParams DecompositionParameters[T]) PrivateFunctionalLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	workSize := inputCount * (e.Parameters.lweDimension + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < inputCount; i++ {
			for j := 0; j < e.Parameters.lweDimension+1; j++ {
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

			in := make([]T, inputCount)
			for jobs := range jobs {
				i, j := jobs[0], jobs[1]

				vec.Fill(in, 0)
				for k := 0; k < decompParams.level; k++ {
					if j == 0 {
						in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
					} else {
						in[i] = e.SecretKey.LWEKey.Value[j-1] << decompParams.ScaledBaseLog(k)
					}
					pfksk.Value[i].Value[j].Value[k].Value[0] = f(in)
					e.EncryptLWEBody(pfksk.Value[i].Value[j].Value[k])
				}
			}
		}(i)
	}
	wg.Wait()

	return pfksk
}

// GenPrivateFunctionalGLWEKeySwitchKey samples a new private functional keyswitch key
// for GLWE private keyswitching.
//
// The function f has the form f(in []T, out Poly[T]),
// where length of in is always inputCount.
// The initial value of out is undefined.
//
// This can take a long time.
// Use GenPrivateFunctionalGLWEKeySwitchKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenPrivateFunctionalGLWEKeySwitchKey(inputCount int, f func([]T, poly.Poly[T]), decompParams DecompositionParameters[T]) PrivateFunctionalGLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalGLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	in := make([]T, inputCount)
	for i := 0; i < inputCount; i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			for k := 0; k < decompParams.level; k++ {
				if j == 0 {
					in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
				} else {
					in[i] = e.SecretKey.LWEKey.Value[j-1] << decompParams.ScaledBaseLog(k)
				}
				f(in, pfksk.Value[i][j].Value[k].Value[0])
				e.EncryptGLWEBody(pfksk.Value[i][j].Value[k])
			}
		}
		in[i] = 0
	}

	return pfksk
}

// GenPrivateFunctionalGLWEKeySwitchKeyParallel samples a new private functional keyswitch key
// for GLWE private keyswitching in parallel.
//
// The function f has the form f(in []T, out Poly[T]),
// where length of in is always inputCount.
// The initial value of out is undefined.
// f should also be thread-safe.
func (e *Encryptor[T]) GenPrivateFunctionalGLWEKeySwitchKeyParallel(inputCount int, f func([]T, poly.Poly[T]), decompParams DecompositionParameters[T]) PrivateFunctionalGLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalGLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	workSize := inputCount * (e.Parameters.lweDimension + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan [2]int)
	go func() {
		defer close(jobs)
		for i := 0; i < inputCount; i++ {
			for j := 0; j < e.Parameters.lweDimension+1; j++ {
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

			in := make([]T, inputCount)
			for jobs := range jobs {
				i, j := jobs[0], jobs[1]

				vec.Fill(in, 0)
				for k := 0; k < decompParams.level; k++ {
					if j == 0 {
						in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
					} else {
						in[i] = e.SecretKey.LWEKey.Value[j-1] << decompParams.ScaledBaseLog(k)
					}
					f(in, pfksk.Value[i][j].Value[k].Value[0])
					e.EncryptGLWEBody(pfksk.Value[i][j].Value[k])
				}
			}
		}(i)
	}
	wg.Wait()

	return pfksk
}

// GenPublicFunctionalLWEKeySwitchKey samples a new public functional keyswitch key
// for LWE public keyswitching.
//
// This can take a long time.
// Use GenPublicFunctionalLWEKeySwitchKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenPublicFunctionalLWEKeySwitchKey(decompParams DecompositionParameters[T]) PublicFunctionalLWEKeySwitchKey[T] {
	pfksk := NewPublicFunctionalLWEKeySwitchKey(e.Parameters, decompParams)

	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < decompParams.level; j++ {
			pfksk.Value[i].Value[j].Value[0] = e.SecretKey.LWEKey.Value[i] << decompParams.ScaledBaseLog(j)
			e.EncryptLWEBody(pfksk.Value[i].Value[j])
		}
	}

	return pfksk
}

// GenPublicFunctionalLWEKeySwitchKeyParallel samples a new public functional keyswitch key
// for LWE public keyswitching in parallel.
func (e *Encryptor[T]) GenPublicFunctionalLWEKeySwitchKeyParallel(decompParams DecompositionParameters[T]) PublicFunctionalLWEKeySwitchKey[T] {
	pfksk := NewPublicFunctionalLWEKeySwitchKey(e.Parameters, decompParams)

	workSize := e.Parameters.lweDimension
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := 0; i < e.Parameters.lweDimension; i++ {
			jobs <- i

		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(chunkIdx int) {
			defer wg.Done()
			e := encryptorPool[chunkIdx]

			for i := range jobs {
				for j := 0; j < decompParams.level; j++ {
					pfksk.Value[i].Value[j].Value[0] = e.SecretKey.LWEKey.Value[i] << decompParams.ScaledBaseLog(j)
					e.EncryptLWEBody(pfksk.Value[i].Value[j])
				}
			}
		}(i)
	}
	wg.Wait()

	return pfksk
}

// GenPublicFunctionalGLWEKeySwitchKey samples a new public functional keyswitch key
// for GLWE public keyswitching.
//
// This can take a long time.
// Use GenPublicFunctionalGLWEKeySwitchKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenPublicFunctionalGLWEKeySwitchKey(decompParams DecompositionParameters[T]) PublicFunctionalGLWEKeySwitchKey[T] {
	pfksk := NewPublicFunctionalGLWEKeySwitchKey(e.Parameters, decompParams)

	e.buffer.ctGLWE.Value[0].Clear()
	for i := 0; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < decompParams.level; j++ {
			e.buffer.ctGLWE.Value[0].Clear()
			e.buffer.ctGLWE.Value[0].Coeffs[0] = e.SecretKey.LWEKey.Value[i] << decompParams.ScaledBaseLog(j)
			e.EncryptGLWEBody(e.buffer.ctGLWE)
			e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, pfksk.Value[i].Value[j])
		}
	}

	return pfksk
}

// GenPublicFunctionalGLWEKeySwitchKeyParallel samples a new public functional keyswitch key
// for GLWE public keyswitching in parallel.
func (e *Encryptor[T]) GenPublicFunctionalGLWEKeySwitchKeyParallel(decompParams DecompositionParameters[T]) PublicFunctionalGLWEKeySwitchKey[T] {
	pfksk := NewPublicFunctionalGLWEKeySwitchKey(e.Parameters, decompParams)

	workSize := e.Parameters.lweDimension
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encryptorPool := make([]*Encryptor[T], chunkCount)
	for i := range encryptorPool {
		encryptorPool[i] = e.ShallowCopy()
	}

	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := 0; i < e.Parameters.lweDimension; i++ {
			jobs <- i

		}
	}()

	var wg sync.WaitGroup
	wg.Add(chunkCount)
	for i := 0; i < chunkCount; i++ {
		go func(chunkIdx int) {
			defer wg.Done()
			e := encryptorPool[chunkIdx]

			for i := range jobs {
				for j := 0; j < decompParams.level; j++ {
					e.buffer.ctGLWE.Value[0].Clear()
					e.buffer.ctGLWE.Value[0].Coeffs[0] = e.SecretKey.LWEKey.Value[i] << decompParams.ScaledBaseLog(j)
					e.EncryptGLWEBody(e.buffer.ctGLWE)
					e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, pfksk.Value[i].Value[j])
				}
			}
		}(i)
	}
	wg.Wait()

	return pfksk
}

// GenCircuitBootstrapKey samples a new circuit bootstrap key.
//
// This can take a long time.
// Use GenPublicFunctionalGLWEKeySwitchKeyParallel for better key generation performance.
func (e *Encryptor[T]) GenCircuitBootstrapKey(decompParams DecompositionParameters[T]) CircuitBootstrapKey[T] {
	cbsk := CircuitBootstrapKey[T]{decompParams: decompParams}
	cbsk.Value = make([]PrivateFunctionalGLWEKeySwitchKey[T], e.Parameters.glweDimension+1)

	cbsk.Value[0] = e.GenPrivateFunctionalGLWEKeySwitchKey(1, func(t []T, p poly.Poly[T]) {
		p.Clear()
		p.Coeffs[0] = t[0]
	}, decompParams)

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		cbsk.Value[i] = e.GenPrivateFunctionalGLWEKeySwitchKey(1, func(t []T, p poly.Poly[T]) {
			k := e.SecretKey.GLWEKey.Value[i-1]
			for i := 0; i < e.Parameters.polyDegree; i++ {
				p.Coeffs[i] = -t[0] * k.Coeffs[i]
			}
		}, decompParams)
	}

	return cbsk
}

// GenCircuitBootstrapKeyParallel samples a new circuit bootstrap key in parallel.
func (e *Encryptor[T]) GenCircuitBootstrapKeyParallel(decompParams DecompositionParameters[T]) CircuitBootstrapKey[T] {
	cbsk := CircuitBootstrapKey[T]{decompParams: decompParams}
	cbsk.Value = make([]PrivateFunctionalGLWEKeySwitchKey[T], e.Parameters.glweDimension+1)

	cbsk.Value[0] = e.GenPrivateFunctionalGLWEKeySwitchKeyParallel(1, func(t []T, p poly.Poly[T]) {
		p.Clear()
		p.Coeffs[0] = t[0]
	}, decompParams)

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		cbsk.Value[i] = e.GenPrivateFunctionalGLWEKeySwitchKeyParallel(1, func(t []T, p poly.Poly[T]) {
			k := e.SecretKey.GLWEKey.Value[i-1]
			for i := 0; i < e.Parameters.polyDegree; i++ {
				p.Coeffs[i] = -t[0] * k.Coeffs[i]
			}
		}, decompParams)
	}

	return cbsk
}

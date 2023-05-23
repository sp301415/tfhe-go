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
func (e Encrypter[T]) GenPrivateFunctionalLWEKeySwitchKey(inputCount int, f func([]T) T, decompParams DecompositionParameters[T]) PrivateFunctionalLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	in := make([]T, inputCount)
	for i := 0; i < inputCount; i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			for k := 0; k < decompParams.level; k++ {
				if j == 0 {
					in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
				} else {
					in[i] = e.lweKey.Value[j-1] << decompParams.ScaledBaseLog(k)
				}
				pfksk.Value[i].Value[j].Value[k].Value[0] = f(in)
				e.EncryptLWEAssign(pfksk.Value[i].Value[j].Value[k])
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
func (e Encrypter[T]) GenPrivateFunctionalLWEKeySwitchKeyParallel(inputCount int, f func([]T) T, decompParams DecompositionParameters[T]) PrivateFunctionalLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	workSize := inputCount * (e.Parameters.lweDimension + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encrypterPool := make([]Encrypter[T], chunkCount)
	for i := range encrypterPool {
		encrypterPool[i] = e.ShallowCopy()
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
			e := encrypterPool[chunkIdx]

			in := make([]T, inputCount)
			for jobs := range jobs {
				i, j := jobs[0], jobs[1]

				vec.Fill(in, 0)
				for k := 0; k < decompParams.level; k++ {
					if j == 0 {
						in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
					} else {
						in[i] = e.lweKey.Value[j-1] << decompParams.ScaledBaseLog(k)
					}
					pfksk.Value[i].Value[j].Value[k].Value[0] = f(in)
					e.EncryptLWEAssign(pfksk.Value[i].Value[j].Value[k])
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
func (e Encrypter[T]) GenPrivateFunctionalGLWEKeySwitchKey(inputCount int, f func([]T, poly.Poly[T]), decompParams DecompositionParameters[T]) PrivateFunctionalGLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalGLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	in := make([]T, inputCount)
	for i := 0; i < inputCount; i++ {
		for j := 0; j < e.Parameters.lweDimension+1; j++ {
			for k := 0; k < decompParams.level; k++ {
				if j == 0 {
					in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
				} else {
					in[i] = e.lweKey.Value[j-1] << decompParams.ScaledBaseLog(k)
				}
				f(in, pfksk.Value[i][j].Value[k].Value[0])
				e.EncryptGLWEAssign(pfksk.Value[i][j].Value[k])
			}
		}
		in[i] = 0
	}

	return pfksk
}

// GenPrivateFunctionalLWEKeySwitchKeyParallel samples a new private functional keyswitch key
// for GLWE private keyswitching in parallel.
//
// The function f has the form f(in []T, out Poly[T]),
// where length of in is always inputCount.
// The initial value of out is undefined.
// f should also be thread-safe.
func (e Encrypter[T]) GenPrivateFunctionalGLWEKeySwitchKeyParallel(inputCount int, f func([]T, poly.Poly[T]), decompParams DecompositionParameters[T]) PrivateFunctionalGLWEKeySwitchKey[T] {
	pfksk := NewPrivateFunctionalGLWEKeySwitchKey(e.Parameters, inputCount, decompParams)

	workSize := inputCount * (e.Parameters.lweDimension + 1)
	chunkCount := num.Min(runtime.NumCPU(), num.Sqrt(workSize))

	encrypterPool := make([]Encrypter[T], chunkCount)
	for i := range encrypterPool {
		encrypterPool[i] = e.ShallowCopy()
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
			e := encrypterPool[chunkIdx]

			in := make([]T, inputCount)
			for jobs := range jobs {
				i, j := jobs[0], jobs[1]

				vec.Fill(in, 0)
				for k := 0; k < decompParams.level; k++ {
					if j == 0 {
						in[i] = (T(0) - 1) << decompParams.ScaledBaseLog(k)
					} else {
						in[i] = e.lweKey.Value[j-1] << decompParams.ScaledBaseLog(k)
					}
					f(in, pfksk.Value[i][j].Value[k].Value[0])
					e.EncryptGLWEAssign(pfksk.Value[i][j].Value[k])
				}
			}
		}(i)
	}
	wg.Wait()

	return pfksk
}

package tfhe

import "github.com/sp301415/tfhe/math/poly"

// Evaluater handles homomorphic operation of values.
// This is meant to be public.
type Evaluater[T Tint] struct {
	params Parameters[T]

	polyEvaluater poly.Evaluater[T]
}

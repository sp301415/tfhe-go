package tfhe

// GGSWCiphertext represents an encrypted GGSW ciphertext.
// GGSW ciphertext is a collection of leveled GLWE ciphertexts,
// ordered as [k][l]GLWECiphertext.
type GGSWCiphertext[T Tint] struct {
	value [][]GLWECiphertext[T]
}

package main

import (
	"fmt"

	"github.com/sp301415/tfhe/tfhe"
)

func main() {
	// Choose Parameters from default parameters
	params := tfhe.ParamsMessage4Carry0

	// Create Encrypter, which should be private
	enc := tfhe.NewEncrypter(params)

	// Encrypt a message to LWE ciphertext,
	// which is the default form of encryption
	message := 13
	lweCt := enc.MustEncrypt(message)

	// Decrypt the message
	decryptedMessage := enc.Decrypt(lweCt)
	fmt.Println("LWE Decryption:", decryptedMessage)

	// We can pack multiple messages into GLWE ciphertexts.
	messages := []int{1, 1, 2, 3, 5, 8, 13}
	glweCt := enc.MustEncryptPacked(messages)

	decryptedMessages := enc.DecryptPacked(glweCt)[:len(messages)]
	fmt.Println("GLWE Decryption:", decryptedMessages)
}

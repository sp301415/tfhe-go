package main

import (
	"fmt"

	"github.com/sp301415/tfhe"
)

func main() {
	enc := tfhe.NewEncrypter(tfhe.BooleanParameters)

	msg := []int{1, 0, 1, 1, 0}

	ct := enc.EncryptGLWE(msg)
	pt := enc.DecryptGLWE(ct)

	fmt.Println(pt)

}

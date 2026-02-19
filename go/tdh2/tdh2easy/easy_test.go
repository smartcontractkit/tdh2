/*
Copy go/tdh2/cmd/demo/main.go from fork by WenxingDuan
https://github.com/WenxingDuan/tdh2/blob/codex/create-demo-for-threshold-encryption-and-decryption/go/tdh2/cmd/demo/main.go
and convert into a esay_test.go, similar to tdh2/tdh2hybridCCP/hybrid_test.go.
*/

package main

import (
	"fmt"

	tdh2easy "github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
)

func main() {
	// server generates keys and distributes shares to n nodes with threshold k
	k, n := 3, 5
	_, pk, shares, err := tdh2easy.GenerateKeys(k, n)
	if err != nil {
		panic(fmt.Errorf("generate keys: %w", err))
	}

	// client encrypts a message using the public key
	msg := []byte("hello threshold encryption")
	ctxt, err := tdh2easy.Encrypt(pk, msg)
	if err != nil {
		panic(fmt.Errorf("encrypt: %w", err))
	}

	// nodes create decryption shares for the ciphertext
	decShares := make([]*tdh2easy.DecryptionShare, 0, k)
	for i := 0; i < k; i++ {
		ds, err := tdh2easy.Decrypt(ctxt, shares[i])
		if err != nil {
			panic(fmt.Errorf("decrypt share %d: %w", i, err))
		}
		decShares = append(decShares, ds)
	}

	// server verifies shares and combines them to recover the message
	for _, s := range decShares {
		if err := tdh2easy.VerifyShare(ctxt, pk, s); err != nil {
			panic(fmt.Errorf("verify share: %w", err))
		}
	}
	recovered, err := tdh2easy.Aggregate(ctxt, decShares, n)
	if err != nil {
		panic(fmt.Errorf("aggregate: %w", err))
	}

	fmt.Printf("Original message: %s\n", msg)
	fmt.Printf("Recovered message: %s\n", recovered)
}

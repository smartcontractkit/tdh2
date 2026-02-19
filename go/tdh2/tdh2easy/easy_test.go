/*
Copy go/tdh2/cmd/demo/main.go from old fork by @WenxingDuan
https://github.com/WenxingDuan/tdh2/blob/codex/create-demo-for-threshold-encryption-and-decryption/go/tdh2/cmd/demo/main.go
and convert into a tdh2easy/easy_test.go, similar to tdh2hybridCCP/hybrid_test.go.

ToDo: Re-key with Redeal() using Master Key (ms) and eventually different k, n.
Then repeat tests with existing & new collective Public Keys, as well as
new n individual Private Key Shares.
*/
package tdh2easy

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEasy(t *testing.T) {
	// Optional: Rename this to 'func main() {...}' to convert to
	// a self-contained Go program. Also replace 't.' by 'log.' and
	// add prefix 'tdh2easy.' to import functions & objects.
	// Alternatively, rename it to 'func ExampleEasy()' or similar to test
	// only for final output, see https://pkg.go.dev/testing#hdr-Examples

	// server generates keys and distributes shares to n nodes with threshold k
	//k, n := 3, 5
	k, n := 7, 11
	//k, n := 99, 120
	//k, n := 121, 120
	//ms, pk, shares, err := GenerateKeys(k, n)
	_, pk, shares, err := GenerateKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// client encrypts a message using the public key
	msg := []byte("hybrid threshold cryptography")
	ctxt, err := Encrypt(pk, msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// min. k of n nodes create decryption shares of the ciphertext
	decShares := make([]*DecryptionShare, 0, n) // ask all n node to compute
	//decShares := make([]*DecryptionShare, 0, k) // ask min. threshold k only
	for i := 0; i < k; i++ { // try any shares between k and n
		ds, err := Decrypt(ctxt, shares[i])
		if err != nil {
			t.Fatalf("Decryption of share %d failed: %v", i, err)
		}
		decShares = append(decShares, ds)
	}

	// server verifies shares and combines them to recover the message
	for _, s := range decShares {
		if err := VerifyShare(ctxt, pk, s); err != nil {
			t.Fatalf("Verify share failed: %v", err)
		}
	}
	recovered, err := Aggregate(ctxt, decShares, n)
	if err != nil {
		t.Fatalf("Aggregation of shares failed: %v", err)
	}
	if !bytes.Equal(recovered, msg) {
		t.Fatalf("decrypeted message does not match cleartext\n  got: %#v\n want: %#v", recovered, msg)
	}
	fmt.Printf("Original message: %s\n", msg)
	fmt.Printf("Recovered message: %s\n", recovered)
}

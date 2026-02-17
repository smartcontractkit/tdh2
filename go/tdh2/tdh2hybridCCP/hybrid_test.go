package tdh2hybridCCP

import (
	"fmt"
	"testing"
)

func TestHybrid(t *testing.T) {
	// Optional: rename this to 'func main() {...}' to convert to
	// a self-contained Go program. Also replace 't.' by 'log.' and
	// add prefix 'tdh2hybridCCP.' to import functions & objects.

	// 1. Setup: Define the threshold (k) and total participants (n).
	// We need at least 2 people to decrypt out of 3 total.
	var k, n int = 2, 3

	// Perform a distributed key generation (DKG) protocol to create a
	// Master Secret, a collective Public Key, and n individual
	// Private Key Shares.
	// Note: The Master Secret (ms) returned is ignored here, but it will
	// be required for re-keying by Redeal(pk, ms, k, n).
	//ms, pubKey, privShares, err := tdh2hybridCCP.GenerateKeys(k, n)
	_, pubKey, privShares, err := GenerateKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// 2. Encryption
	message := []byte("The quick brown fox jumps over the lazy dog's back 0123456789.")

	// Anyone can encrypt using the Public Key only.
	//cipherText, err := Encrypt(pubKey, message)
	aaData := []byte("tests additional authenticated, but not encrypted metadata")
	//cipherText, err := tdh2ccp.EncryptWithAaD(pubKey, message, aaData)
	cipherText, err := EncryptWithAaD(pubKey, message, aaData)
	//var emptyLabel [tdh2.InputSize]byte
	//cipherText, err := EncryptWithLabelAndAaD(pubKey, message, emptyLabel, aaData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	fmt.Println("Message encrypted successfully.")

	// 3. Decryption of all n shares
	// Each participant creates a 'decryption share' from the ciphertext
	// using their own private key share, returns a *DecryptionShare.
	share0, err := Decrypt(cipherText, privShares[0])
	if err != nil {
		t.Fatalf("Decryption share0 by party 0 failed: %v", err)
	}
	share1, err := Decrypt(cipherText, privShares[1])
	//_ = share0	// facilitate tesing with 2 out of 3 only if share0 unused, obsoleted by VerifyShare()
	if err != nil {
		t.Fatalf("Decryption share1 by party 1 failed: %v", err)
	}
	//_ = share1	// facilitate tesing with 2 out of 3 only if share1 unused, obsoleted by VerifyShare()
	share2, err := Decrypt(cipherText, privShares[2])
	if err != nil {
		t.Fatalf("Decryption share2 by party 2 failed: %v", err)
	}
	//_ = share2	// facilitate tesing with 2 out of 3 only if share2 unused, obsoleted by VerifyShare()

	// 4. Verification: Combiner verifies decrypted shares before aggregating them.
	// Observe comment from Aggregate(): "Ciphertext and shares MUST be verified
	// before calling Aggregate ..."
	err = VerifyShare(cipherText, pubKey, share0)
	if err != nil {
		t.Fatalf("Verify share0 by combiner failed: %v", err)
	}
	err = VerifyShare(cipherText, pubKey, share1)
	if err != nil {
		t.Fatalf("Verify share1 by combiner failed: %v", err)
	}
	err = VerifyShare(cipherText, pubKey, share2)
	if err != nil {
		t.Fatalf("Verify share2 by combiner failed: %v", err)
	}

	// 5. Aggregation: Combine min. k of n decrypted shares to recover the
	// original message in cleartext.

	// Create a slice of the pointers, not a slice of byte slices.
	// All the shares have to be distinct and their number has to be
	// at least the threshold k.
	//decryptionShares := []*tdh2easy.DecryptionShare{share0, share1}	// prefix with package name!
	//decryptionShares := []*DecryptionShare{share0, share1}
	decryptionShares := []*DecryptionShare{share0, share2}
	//decryptionShares := []*DecryptionShare{share1, share2}
	//decryptionShares := []*DecryptionShare{share0, share1, share2} // also works OK
	// makes Aggregate() fail:
	//decryptionShares := []*DecryptionShare{share1, share1} // shares not distinct
	//decryptionShares := []*DecryptionShare{share1, share1, share2} // shares not distinct
	//decryptionShares := []*DecryptionShare{share1} // fewer shares than threshold k

	decryptedMsg, err := Aggregate(cipherText, decryptionShares, n)
	if err != nil {
		t.Fatalf("Aggregation failed: %v", err)
	}
	fmt.Printf("Decrypted Message: %s\n", string(decryptedMsg))
}

package tdh2hybridCCP

import (
	"fmt"
	"log"
	"testing"

	//tdh2ccp "github.com/smartcontractkit/tdh2/go/tdh2/tdh2hybridCCP"
	//tdh2ccp "github.com/hb9cwp/tdh2/go/tdh2/tdh2hybridCCP"
	// $ go get github.com/hb9cwp/tdh2/go/tdh2/tdh2hybridCCP@hybridCCP
	tdh2ccp "github.com/hb9cwp/tdh2/go/tdh2/tdh2hybridCCP"
)

func TestHybrid(t *testing.T) {
	// 1. Setup: Define the threshold (k) and total participants (n).
	// We need at least 2 people to decrypt out of 3 total.
	var k, n int = 2, 3

	// Generate the Master Secret (ignored), Public Key, and n Private Key Shares.
	//ms, pubKey, privShares, err := tdh2ccp.GenerateKeys(k, n)
	_, pubKey, privShares, err := tdh2ccp.GenerateKeys(k, n)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	// 2. Encryption
	message := []byte("The quick brown fox jumps over the lazy dog's back 0123456789.")

	// Anyone can encrypt using only the Master Public Key.
	//cipherText, err := Encrypt(pubKey, message)
	aaData := []byte("tests additional authenticated, but not encrypted metadata")
	cipherText, err := tdh2ccp.EncryptWithAaD(pubKey, message, aaData)
	//var emptyLabel [tdh2.InputSize]byte
	//cipherText, err := EncryptWithLabelAndAaD(pubKey, message, emptyLabel, aaData)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Println("Message encrypted successfully.")

}

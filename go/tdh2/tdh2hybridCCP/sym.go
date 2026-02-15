package tdh2hybridCCP

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// symKey generates a symmetric key.
func symKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cannot generate key")
	}
	return key, nil
}

// symEncrypt encrypts the message using the ChaCha20Poly1305 AEAD cipher.
func symEncrypt(msg, key, aaData []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot use ChaCha20Poly1305: %w", err)
	}

	// Counter overflow is catastrophic security failure because keystream repeats
	// and attacker can XOR two ciphertexts to cancel out keystream!
	// Never reuse a (key, nonce) pair for more than the limit:
	// * AES-256-GCM block size is 16 byte, max. 2^32 *16 = 64 GB (conservative
	// limit) and RFC 5084 2^36 - 32 bytes ≈ 68.7 GB (theoretical maximum)
	//if uint64(len(msg)) > ((1<<32)-2)*uint64(block.BlockSize()) {
	// * ChaCha20-Poly1305 block size is 64 byte, max. 2^32 *16 = 256 GB
	// which allows 4× larger messages than AES-256-GCM.
	// Its block 0 is used by Poly1305:
	if uint64(len(msg)) > ((1<<32)-1)*uint64(64) { //
		return nil, nil, fmt.Errorf("message too long")
	}
	// * XChaCha20-Poly1305 (Extended Nonce Variant) uses a 64-bit counter
	// instead of 32-bit, and nonce size of 24 vs 12 bytes. Its block
	// size is also 64 byte, max 2^64 *64 ≈ 1.18 × 10^21 bytes (1 Zettabyte!)
	// which is far beyond any practical use case, e.g. practically unlimited.

	// Generate random nonce (12 bytes for ChaCha20Poly1305, same as AES-GCM)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt: prepend nonce to ciphertext is done by passing nonce into first parameter 'dst'
	// Format: [nonce][ciphertext + aaData + authN tag]
	//return aead.Seal(nonce, nonce, msg, nil), nonce, nil // returns (ctxt, nonce, err)
	return aead.Seal(nonce, nonce, msg, aaData), nonce, nil // returns (ctxt, nonce, err)
}

// symDecrypt decrypts the ciphertext using theChaCha20-Poly1305 cipher.
func symDecrypt(nonce, ctxt, key, aaData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20Poly1305 cipher: %w", err)
	}
	if len(ctxt) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonceRecovered := ctxt[:aead.NonceSize()]
	if !bytes.Equal(nonceRecovered, nonce) {
		return nil, fmt.Errorf("nonce mismatch")
	}
	encryptedData := ctxt[aead.NonceSize():]

	// Decrypt and verify: AEAD authenticates additional, non-encrypted aaData which
	// detects which detects any tampering with metadata
	//return aead.Open(nil, nonceRecovered, encryptedData, nil) // authN fails if aaData was set
	return aead.Open(nil, nonceRecovered, encryptedData, aaData)
}

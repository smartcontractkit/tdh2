package decryptionplugin

import "errors"

var ErrNotFound = errors.New("not found")

type CiphertextId = []byte

type DecryptionRequest struct {
	CiphertextId CiphertextId
	Ciphertext   []byte
}

type DecryptionQueuingService interface {
	// GetRequests returns up to requestCountLimit oldest pending requests
	// with total size up to totalBytesLimit bytes size.
	GetRequests(requestCountLimit int, totalBytesLimit int) []DecryptionRequest

	// GetCiphertext returns the ciphertext matching ciphertextId
	// if it exists in the queue.
	// If the ciphertext does not exist it returns ErrNotFound.
	GetCiphertext(ciphertextId CiphertextId) ([]byte, error)

	// SetResult sets the plaintext (decrypted ciphertext) which corresponds to ciphertextId.
	SetResult(ciphertextId CiphertextId, plaintext []byte)
}

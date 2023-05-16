package decryptionplugin

type CiphertextId = []byte

type DecryptionRequest struct {
	ciphertextId CiphertextId
	ciphertext   []byte
}

type DecryptionQueuingService interface {
	// GetRequests returns up to requestCountLimit oldest pending requests
	// with total size up to totalBytesLimit bytes size.
	GetRequests(requestCountLimit int, totalBytesLimit int) []DecryptionRequest

	// GetCiphertext returns the ciphertext matching ciphertextId
	// if it exists in the queue.
	GetCiphertext(ciphertextId CiphertextId) ([]byte, error)

	// ReturnResult returns the plaintext (decrypted ciphertext) which corresponds to ciphertextId
	// to the queueing service.
	ReturnResult(ciphertextId CiphertextId, plaintext []byte)
}

package decryptionplugin

type CiphertextId = []byte

type DecryptionRequest struct {
	ciphertextId CiphertextId
	ciphertext   []byte
}

type DecryptionQueuingService interface {
	GetRequests(requestCountLimit int, totalBytesLimit int) []DecryptionRequest
	GetCiphertext(ciphertextId CiphertextId) ([]byte, error)
	ReturnResult(ciphertextId CiphertextId, plaintext []byte)
}

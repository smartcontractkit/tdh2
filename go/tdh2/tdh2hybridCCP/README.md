## tdh2hybridCCP: Hybrid TDH2 and ChaCha20-Poly1305

This fork of /tdh2/tdh2easy provides a hybrid encryption scheme that uses **Threshold Diffie-Hellman (TDH2)** which is secure against adaptive chosen-ciphertext attacks (CCA2), combined with a ***modern symmetric stream cipher*** **ChaCha20-Poly1305** ***instead of*** **AES-256 in Galois/Counter Modem (GCM)**.

### ChaCha20-Poly1305 replaces AES-256-GCM
The modern stream cipher provides:
- Authenticated Encryption with Associated Data (AEAD), also called Additional Authenticated Data (AAD):
  - It encrypts sensitive payload data while allowing additional, authenticated but not encrypted metadata ("associated data") to be authenticated along with the ciphertext which detects any tampering.
  - AEAD has become the standard for securing communication, replacing older, less secure methods that combined encryption and Message Authentication Code (MAC) separately.
- Performance:
  - Stream ciphers are often faster than AES on devices without hardware acceleration.
  - Designed to be fast and efficient, often outperforming separate encryption and authentication mechanisms.
  - Verification during Decryption: If the authentication tag does not match the decrypted data and associated data, the decryption fails, ensuring integrity.
- Support for larger plaintext: up to 256 GB compared to maximum ca. 64 GB with AES (RFC5084).

### Example
The [`func TestHybrid()`](./hybrid_test.go) provides running code that steps through the cycle of Distribted Key Generation (DKG), hybrid encryption of plaintext, decryption of shares by parties and their verification before a combiner aggregates the decryption shares, and finally decrypts the ciphertext.

Run it together with other `*_test.go` files after change into subdir `tdhhybridCCP` of this repo:
```
~/tdh2/go/tdh2/tdh2hybridCCP$ go test 
Message encrypted successfully.
Decrypted Message: The quick brown fox jumps over the lazy dog's back 0123456789.
PASS
ok      github.com/hb9cwp/tdh2/go/tdh2/tdh2hybridCCP  0.109s
```

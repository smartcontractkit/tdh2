package tdh2hybridCCP

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// const keyLength = 16  // AES-GCM supports 128, 192, and 256 bit keys
const keyLength = 32 // ChaCha20-Poly1305 supports 256 bit keys only!

var aaData = []byte("tests additional authenticated, but not encrypted metadata")

func TestSymmetric(t *testing.T) {
	key, err := symKey(keyLength)
	if err != nil {
		t.Fatalf("symmetricKey: %v", err)
	}
	for _, tc := range []struct {
		name string
		msg  []byte
		key  []byte
		aaD  []byte // AEAD metata
		err  error
	}{
		{
			name: "OK (short message)",
			msg:  []byte("msg"),
			key:  key,
		},
		{
			name: "OK with AAData",
			msg:  []byte("msg"),
			aaD:  []byte("metadata"),
			key:  key,
		},
		{
			name: "OK (empty message)",
			key:  key,
		},
		{
			name: "OK (64 k message)",
			msg:  make([]byte, 65536),
			key:  key,
		},
		{
			name: "wrong key length",
			msg:  make([]byte, 65536),
			key:  key[:4],
			err:  cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, nonce, err := symEncrypt(tc.msg, tc.key, aaData)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Errorf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			out, err := symDecrypt(nonce, c, key, aaData)
			if err != nil {
				t.Errorf("symmetricDecryption: %v", err)
			}
			if diff := cmp.Diff(tc.msg, out); diff != "" {
				t.Errorf("encrypted/decrypted message diff=%v", diff)
			}
		})
	}
}

func TestSymmetricDecryptionFail(t *testing.T) {
	msg := []byte("msg")
	key, err := symKey(keyLength)
	if err != nil {
		t.Fatalf("symmetricKey: %v", err)
	}
	c, nonce, err := symEncrypt(msg, key, aaData)
	if err != nil {
		t.Fatalf("symmetricEncryption: %v", err)
	}
	for _, tc := range []struct {
		name  string
		nonce []byte
		c     []byte // ctxt
		key   []byte
		aaD   []byte // AEAD metadata
		err   error
	}{
		{
			name:  "OK",
			key:   key,
			nonce: nonce,
			c:     c,
		},
		{
			name:  "wrong key",
			key:   []byte("key"),
			nonce: nonce,
			c:     c,
			err:   cmpopts.AnyError,
		},
		{
			name:  "wrong nonce",
			key:   key,
			nonce: []byte("nonce"),
			c:     c,
			err:   cmpopts.AnyError,
		},
		{
			name:  "wrong ciphertext",
			key:   key,
			nonce: nonce,
			c:     []byte("ciphertext"),
			err:   cmpopts.AnyError,
		},
		{
			name: "wrong AAD",
			key:  key,
			aaD:  []byte("wrong"),
			c:    c,
		},
		{
			name: "nil AAD when AAD was used",
			key:  key,
			aaD:  nil,
			c:    c,
		},
		{
			name:  "wrong nonce with AAD",
			key:   key,
			aaD:   aaData,
			nonce: []byte("nonce"),
			c:     c,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := symDecrypt(nonce, c, key, aaData)
			if err != nil {
				t.Errorf("symmetricDecryption: %v", err)
			}
			if diff := cmp.Diff(msg, out); diff != "" {
				t.Errorf("encrypted/decrypted message diff=%v", diff)
			}
		})
	}
}

func FuzzSymEncryption(f *testing.F) {
	f.Add(16, []byte("sample message"), aaData)
	f.Add(24, []byte("another sample message"), aaData)
	f.Add(32, []byte("and another sample message"), aaData)
	f.Fuzz(func(t *testing.T, keySize int, msg []byte, aaD []byte) {
		//if keySize != 16 && keySize != 24 && keySize != 32 { // AES-GCM
		if keySize != keyLength { // ChaCha20-Poly1305
			t.Skip()
		}
		key, err := symKey(keySize)
		if err != nil {
			t.Fatalf("symKey(%v): %v", keySize, err)
		}
		c, n, err := symEncrypt(msg, key, aaData)
		if err != nil {
			t.Fatalf("symEncrypt(%v, %v): %v", msg, key, err)
		}
		p, err := symDecrypt(n, c, key, aaData)
		if err != nil {
			t.Fatalf("symDecryt(%v, %v, %v): %v", n, c, key, err)
		}
		if d := cmp.Diff(p, msg); d != "" {
			t.Fatalf("got/want diff=%v", d)
		}
		// Verify wrong AAD causes failure
		if len(aaD) > 0 {
			wrongAAD := make([]byte, len(aaD))
			copy(wrongAAD, aaD)
			wrongAAD[0] ^= 0x42 // inject errors
			_, err = symDecrypt(n, c, key, wrongAAD)
			if err == nil {
				t.Fatal("Expected error with wrong AAD")
			}
		}
	})
}

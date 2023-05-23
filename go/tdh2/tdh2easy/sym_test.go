package tdh2easy

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestSymmetric(t *testing.T) {
	key, err := symKey(16)
	if err != nil {
		t.Fatalf("symmetricKey: %v", err)
	}
	for _, tc := range []struct {
		name string
		msg  []byte
		key  []byte
		err  error
	}{
		{
			name: "OK",
			msg:  []byte("msg"),
			key:  key,
		},
		{
			name: "OK (empty)",
			key:  key,
		},
		{
			name: "OK (long)",
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
			c, nonce, err := symEncrypt(tc.msg, tc.key)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Errorf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			out, err := symDecrypt(nonce, c, key)
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
	key, err := symKey(16)
	if err != nil {
		t.Fatalf("symmetricKey: %v", err)
	}
	c, nonce, err := symEncrypt(msg, key)
	if err != nil {
		t.Fatalf("symmetricEncryption: %v", err)
	}
	for _, tc := range []struct {
		name  string
		nonce []byte
		c     []byte
		key   []byte
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
			name:  "wrong c",
			key:   key,
			nonce: nonce,
			c:     []byte("ciphertext"),
			err:   cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := symDecrypt(nonce, c, key)
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
	f.Add(16, []byte("sample message"))
	f.Add(24, []byte("another sample message"))
	f.Add(32, []byte("and another sample message"))
	f.Fuzz(func(t *testing.T, keySize int, msg []byte) {
		if keySize != 16 && keySize != 24 && keySize != 32 {
			t.Skip()
		}
		key, err := symKey(keySize)
		if err != nil {
			t.Fatalf("symKey(%v): %v", keySize, err)
		}
		c, n, err := symEncrypt(msg, key)
		if err != nil {
			t.Fatalf("symEncrypt(%v, %v): %v", msg, key, err)
		}
		p, err := symDecrypt(n, c, key)
		if err != nil {
			t.Fatalf("symDecryt(%v, %v, %v): %v", n, c, key, err)
		}
		if d := cmp.Diff(p, msg); d != "" {
			t.Fatalf("got/want diff=%v", d)
		}
	})
}

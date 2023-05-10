package tdh2easy

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smartcontractkit/libtdh2/go/tdh2"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

func TestCiphertextDecrypt(t *testing.T) {
	_, pk, share, err := GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	_, _, wrong, err := tdh2.GenerateKeys(nist.NewBlakeSHA256QR512(), nil, 1, 1, keccak.New(nil))
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	c, err := Encrypt(pk, []byte("msg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c.Decrypt(share[0]); err != nil {
		t.Errorf("Decrypt: %v", err)
	}
	if _, err := c.Decrypt(wrong[0]); err == nil {
		t.Errorf("Decrypt did not fail")
	}
}

func TestCiphertextVerifyShare(t *testing.T) {
	_, pk, share, err := GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	_, _, wrongShare, err := GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	c, err := Encrypt(pk, []byte("msg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ds, err := c.Decrypt(share[0])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	wrongDs, err := c.Decrypt(wrongShare[0])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if err := c.VerifyShare(pk, ds); err != nil {
		t.Errorf("VerifyShare: %v", err)
	}
	if err := c.VerifyShare(pk, wrongDs); err == nil {
		t.Errorf("VerifyShare did not fail")
	}
}

func TestAggregate(t *testing.T) {
	k := 3
	n := 5
	_, pk, shares, err := GenerateKeys(k, n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	msg := []byte("message")
	c, err := Encrypt(pk, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	decShares := make([]*tdh2.DecryptionShare, n)
	for i := range shares {
		ds, err := c.Decrypt(shares[i])
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		decShares[i] = ds
	}
	for _, tc := range []struct {
		name   string
		ctxt   *Ciphertext
		shares []*tdh2.DecryptionShare
		err    error
	}{
		{
			name:   "OK (all shares)",
			ctxt:   c,
			shares: decShares,
		},
		{
			name:   "OK (min shares)",
			ctxt:   c,
			shares: decShares[:k],
		},
		{
			name:   "not enough shares",
			ctxt:   c,
			shares: decShares[:2],
			err:    cmpopts.AnyError,
		},
		{
			name: "wrong nonce",
			ctxt: &Ciphertext{
				tdh2Ctxt: c.tdh2Ctxt,
				symCtxt:  c.symCtxt,
				nonce:    make([]byte, len(c.nonce)),
			},
			shares: decShares,
			err:    cmpopts.AnyError,
		},
		{
			name: "wrong nonce size",
			ctxt: &Ciphertext{
				tdh2Ctxt: c.tdh2Ctxt,
				symCtxt:  c.symCtxt,
				nonce:    []byte("nonce"),
			},
			shares: decShares,
			err:    cmpopts.AnyError,
		},
		{
			name: "wrong symmetric ciphertext",
			ctxt: &Ciphertext{
				tdh2Ctxt: c.tdh2Ctxt,
				symCtxt:  []byte("ciphertext"),
				nonce:    c.nonce,
			},
			shares: decShares,
			err:    cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.ctxt.Aggregate(tc.shares, n)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Errorf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			if diff := cmp.Diff(msg, out); diff != "" {
				t.Errorf("encrypted decrypted message diff=%v", diff)
			}
		})
	}
}

func TestCiphertextMarshal(t *testing.T) {
	_, pk, _, err := GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	want, err := Encrypt(pk, []byte("msg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Ciphertext
	if err := got.UnmarshalVerify(b, pk); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if d := cmp.Diff(got.symCtxt, want.symCtxt); d != "" {
		t.Errorf("got/want Ciphertext diff=%v", d)
	}
	if d := cmp.Diff(got.nonce, want.nonce); d != "" {
		t.Errorf("got/want Nonce diff=%v", d)
	}
	if !got.tdh2Ctxt.Equal(want.tdh2Ctxt) {
		t.Errorf("different ciphertexts")
	}
}

func TestCiphertextUnmarshal(t *testing.T) {
	_, pk, _, err := GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	_, wrong, _, err := GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	c, err := Encrypt(pk, []byte("msg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	cRaw, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	brokenTdh2, err := json.Marshal(&ciphertextRaw{
		TDH2Ctxt: []byte("broken"),
		SymCtxt:  []byte("ciphertext"),
		Nonce:    []byte("nonce"),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		pk   *tdh2.PublicKey
		err  error
	}{
		{
			name: "ok",
			raw:  cRaw,
			pk:   pk,
		},
		{
			name: "wrong pk",
			raw:  cRaw,
			pk:   wrong,
			err:  cmpopts.AnyError,
		},
		{
			name: "broken",
			raw:  []byte("broken"),
			pk:   pk,
			err:  cmpopts.AnyError,
		},
		{
			name: "broken tdh2 ciphertext",
			raw:  brokenTdh2,
			pk:   pk,
			err:  cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hc Ciphertext
			if err := hc.UnmarshalVerify(tc.raw, tc.pk); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Errorf("got err=%v, want=%v", err, tc.err)
			}
		})
	}
}

func TestRedealEncryptNew(t *testing.T) {
	ms, pk, _, err := GenerateKeys(3, 5)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	want := []byte("msg")
	for _, tc := range []struct {
		name string
		k, n int
	}{
		{
			name: "same n,k",
			k:    3,
			n:    5,
		},
		{
			name: "smaller quorum",
			k:    2,
			n:    5,
		},
		{
			name: "larger quorum",
			k:    4,
			n:    5,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// generate new instance
			newPk, shares, err := Redeal(pk, ms, tc.k, tc.n)
			if err != nil {
				t.Fatalf("Redeal: %v", err)
			}
			// encrypt and decrypt using new keys
			c, err := Encrypt(newPk, want)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			ds := []*tdh2.DecryptionShare{}
			for _, sh := range shares {
				d, err := c.Decrypt(sh)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if err := c.VerifyShare(newPk, d); err != nil {
					t.Fatalf("VerifyShare: %v", err)
				}
				ds = append(ds, d)
			}
			if got, err := c.Aggregate(ds[:tc.k], tc.n); err != nil {
				t.Errorf("Aggregate: %v", err)
			} else if !cmp.Equal(got, want) {
				t.Errorf("got=%v, want=%v", got, want)
			}
		})
	}
}

func TestRedealDecryptOld(t *testing.T) {
	ms, pk, _, err := GenerateKeys(3, 5)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	want := []byte("msg")
	c, err := Encrypt(pk, want)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for _, tc := range []struct {
		name string
		k, n int
	}{
		{
			name: "same n,k",
			k:    3,
			n:    5,
		},
		{
			name: "smaller quorum",
			k:    2,
			n:    5,
		},
		{
			name: "larger quorum",
			k:    4,
			n:    5,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// generate new instance
			new, shares, err := Redeal(pk, ms, tc.k, tc.n)
			if err != nil {
				t.Fatalf("Redeal: %v", err)
			}
			// try to decrypt old ciphertext
			ds := []*tdh2.DecryptionShare{}
			for _, sh := range shares {
				d, err := c.Decrypt(sh)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if err := c.VerifyShare(new, d); err != nil {
					t.Fatalf("VerifyShare: %v", err)
				}
				ds = append(ds, d)
			}
			// should fail w/o enough shares
			if _, err := c.Aggregate(ds[:tc.k-1], tc.n); err == nil {
				t.Error("Aggregate did not fail")
			}
			// try with enough shares
			if got, err := c.Aggregate(ds[:tc.k], tc.n); err != nil {
				t.Errorf("Aggregate: %v", err)
			} else if !cmp.Equal(got, want) {
				t.Errorf("got=%v, want=%v", got, want)
			}
		})
	}
}

func TestRedealReuseOldShares(t *testing.T) {
	ms, pk, shares, err := GenerateKeys(3, 5)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	newPk, _, err := Redeal(pk, ms, 3, 5)
	if err != nil {
		t.Fatalf("Redeal: %v", err)
	}
	c, err := Encrypt(newPk, []byte("msg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// use old share for decryption
	ds, err := c.Decrypt(shares[0])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	// make sure old shares cannot be used for new encryptions
	if err := c.VerifyShare(newPk, ds); err == nil {
		t.Error("VerifyShare did not fail")
	}
}

func FuzzCiphertextMarshal(f *testing.F) {
	_, pk, _, err := GenerateKeys(1, 1)
	if err != nil {
		f.Fatalf("Keys: %v", err)
	}
	xof, err := xof()
	if err != nil {
		f.Fatalf("xof: %v", err)
	}
	tdh2Input := make([]byte, tdh2.InputSize)
	f.Add(tdh2Input, []byte("symcCtxt"), []byte("nonce"))
	f.Fuzz(func(t *testing.T, key, symCtxt, nonce []byte) {
		if len(key) != tdh2.InputSize {
			t.Skip()
		}
		tdh2Ctxt, err := tdh2.Encrypt(pk, key, tdh2Input, xof)
		if err != nil {
			t.Fatalf("Encrypt(%v): %v", key, err)
		}
		want := Ciphertext{
			tdh2Ctxt: tdh2Ctxt,
			symCtxt:  symCtxt,
			nonce:    nonce,
		}
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%v): %v", want, err)
		}
		var got Ciphertext
		if err := got.UnmarshalVerify(b, pk); err != nil {
			t.Fatalf("UnmarshalVerify(%v): %v", b, err)
		}
	})
}

func FuzzCiphertextUnmarshal(f *testing.F) {
	_, pk, _, err := GenerateKeys(1, 1)
	if err != nil {
		f.Fatalf("Keys: %v", err)
	}
	tdh2Ctxt, err := tdh2.Encrypt(pk, make([]byte, tdh2.InputSize), make([]byte, tdh2.InputSize), keccak.New(nil))
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	c := Ciphertext{
		tdh2Ctxt: tdh2Ctxt,
		symCtxt:  []byte("symCtxt"),
		nonce:    []byte("nonce"),
	}
	b, err := c.Marshal()
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		var c1, c2 Ciphertext
		if err := c1.UnmarshalVerify(data, pk); err != nil {
			t.Skip()
		}
		data1, err := c1.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := c2.UnmarshalVerify(data1, pk); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := c2.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !bytes.Equal(c1.symCtxt, c2.symCtxt) {
			t.Errorf("c1.symCtxt=%v data1=%v c2.symCtxt=%v data2=%v", c1.symCtxt, data1, c2.symCtxt, data2)

		}
		if !bytes.Equal(c1.nonce, c2.nonce) {
			t.Errorf("c1.nonce=%v data1=%v c2.nonce=%v data2=%v", c1.nonce, data1, c2.nonce, data2)

		}
		if !c1.tdh2Ctxt.Equal(c2.tdh2Ctxt) {
			t.Errorf("c1.tdh2Ctxt=%v data1=%v c2.tdh2Ctxt=%v data2=%v", c1.tdh2Ctxt, data1, c2.tdh2Ctxt, data2)
		}
	})
}

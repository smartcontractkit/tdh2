package tdh2

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

var supportedGroups = []string{
	nist.NewBlakeSHA256P256().String(),
}

type common interface {
	Fatalf(format string, args ...interface{})
}

func params(t common, group string) (kyber.Group, cipher.Stream, []byte, []byte) {
	if _, ok := t.(*testing.T); ok {
		t.(*testing.T).Helper()
	}
	seed := make([]byte, 64)
	if n, err := rand.Read(seed); n != 64 || err != nil {
		t.Fatalf("cannot generate seed; n=%d, err=%v", n, err)
	}
	msg := make([]byte, InputSize)
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	label := make([]byte, InputSize)
	if _, err := rand.Read(label); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	g, err := parseGroup(group)
	if err != nil {
		t.Fatalf("parseGroup: %v", err)
	}
	return g, keccak.New(seed), msg, label
}

func TestConcatenate(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, _, _ := params(t, typ)
		g1 := group.Point().Pick(rand)
		g2 := group.Point().Pick(rand)
		g3 := group.Point().Pick(rand)

		out, err := concatenate(group.String(), g1)
		if err != nil {
			t.Errorf("concatenate(g1): %v", err)
		}
		size := len(out)
		if size == 0 {
			t.Errorf("concatenate(g1): empty output")
		}

		out, err = concatenate(group.String(), g1, g2)
		if err != nil {
			t.Errorf("concatenate(g1, g2): %v", err)
		}
		if len(out) <= size {
			t.Errorf("concatenate(g1, g2): output shorter/equal the previous")
		}
		size = len(out)

		out, err = concatenate(group.String(), g1, g2, g3)
		if err != nil {
			t.Errorf("concatenate(g1, g2, g3): %v", err)
		}
		if len(out) <= size {
			t.Errorf("concatenate(g1, g2, g3): output shorter/equal the previous")
		}
	}
}

func TestXor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		a      []byte
		b      []byte
		expect []byte
		err    error
	}{
		{
			name: "empty",
		},
		{
			name:   "OK",
			a:      []byte{0, 1, 2, 3},
			b:      []byte{4, 5, 6, 7},
			expect: []byte{0 ^ 4, 1 ^ 5, 2 ^ 6, 3 ^ 7},
		},
		{
			name: "mismatch",
			a:    []byte{0, 1, 2, 3},
			b:    []byte{4, 5, 6},
			err:  cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := xor(tc.a, tc.b)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Errorf("err=%v, want=%v", err, tc.err)
			}
			if err == nil && !bytes.Equal(out, tc.expect) {
				t.Errorf("got=%v, expected=%v", out, tc.expect)
			}
		})
	}
}

func TestHash1and4(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, _, _ := params(t, typ)
		g1 := group.Point().Pick(rand)
		g2 := group.Point().Pick(rand)
		g3 := group.Point().Pick(rand)

		out, err := hash1(group.String(), g1)
		if err != nil {
			t.Errorf("hash1: %v", err)
		}
		if len(out) != InputSize {
			t.Errorf("hash1 output size: %d, expect: %d", len(out), InputSize)
		}

		if _, err := hash4(g1, g2, g3, group); err != nil {
			t.Errorf("hash4: %v", err)
		}
	}
}

func TestHash2(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rnd, msg, label := params(t, typ)
		g1 := group.Point().Pick(rnd)
		g2 := group.Point().Pick(rnd)
		g3 := group.Point().Pick(rnd)
		g4 := group.Point().Pick(rnd)

		for _, tc := range []struct {
			name  string
			msg   []byte
			label []byte
			err   error
		}{
			{
				name:  "OK",
				msg:   msg,
				label: label,
			},
			{
				name:  "both short",
				msg:   msg[:InputSize-1],
				label: label[:InputSize-1],
				err:   cmpopts.AnyError,
			},
			{
				name:  "one shorter",
				msg:   msg[:InputSize-2],
				label: label,
				err:   cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				_, err := hash2(tc.msg, tc.label, g1, g2, g3, g4, group)
				if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestGenerateKeys(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, _, _ := params(t, typ)
		for _, tc := range []struct {
			name string
			ms   *MasterSecret
			k    int
			n    int
			err  error
		}{
			{
				name: "0 out of 0",
				err:  cmpopts.AnyError,
			},
			{
				name: "0 out of 1",
				n:    1,
				err:  cmpopts.AnyError,
			},
			{
				name: "1 out of 1",
				k:    1,
				n:    1,
			},
			{
				name: "secret ok",
				ms: &MasterSecret{
					group: group,
					s:     group.Scalar().Pick(rand)},
				k: 1,
				n: 1,
			},
			{
				name: "secret wrong group",
				ms: &MasterSecret{
					group: nist.NewBlakeSHA256QR512(),
					s:     group.Scalar().Pick(rand)},
				k:   1,
				n:   1,
				err: cmpopts.AnyError,
			},
			{
				name: "-1 out of 1",
				k:    -1,
				n:    1,
				err:  cmpopts.AnyError,
			},
			{
				name: "10 out of 9",
				k:    10,
				n:    9,
				err:  cmpopts.AnyError,
			},
			{
				name: "1 out of 10",
				k:    1,
				n:    10,
			},
			{
				name: "5 out of 10",
				k:    7,
				n:    10,
			},
			{
				name: "10 out of 10",
				k:    10,
				n:    10,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				ms, pk, shares, err := GenerateKeys(group, tc.ms, tc.k, tc.n, rand)
				if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				} else if err != nil {
					return
				}
				if len(shares) != tc.n {
					t.Errorf("got %d shares, expected %d", len(shares), tc.n)
				}
				if len(pk.hArray) != tc.n {
					t.Errorf("got %d vk.HArray, expected %d", len(pk.hArray), tc.n)
				}
				if tc.ms != nil && !reflect.DeepEqual(ms, tc.ms) {
					t.Errorf("got secret=%v, want=%v", ms, tc.ms)
				}
			})
		}
	}
}

func TestEncrypt(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(t, typ)
		_, pk, _, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		for _, tc := range []struct {
			name  string
			msg   []byte
			label []byte
			err   error
		}{
			{
				name:  "OK",
				msg:   msg,
				label: label,
			},
			{
				name:  "wrong msg size",
				msg:   []byte("msg"),
				label: label,
				err:   cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				ctxt, err := Encrypt(pk, tc.msg, tc.label, rand)
				if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				} else if err != nil {
					return
				}
				if diff := cmp.Diff(label, ctxt.label); diff != "" {
					t.Errorf("label/ctx.Label diff: %v", diff)
				}
			})
		}
	}
}

func TestDecrypt(t *testing.T) {
	wrong := nist.NewBlakeSHA256QR512()
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(t, typ)
		_, pk, shares, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		ctxt, err := Encrypt(pk, msg, label, rand)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		for _, tc := range []struct {
			name  string
			ctxt  *Ciphertext
			share *PrivateShare
			err   error
		}{
			{
				name:  "OK",
				ctxt:  ctxt,
				share: shares[2],
			},
			{
				name: "wrong share group",
				ctxt: ctxt,
				share: &PrivateShare{
					group: wrong,
					index: shares[2].index,
					v:     shares[2].v,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "wrong group",
				ctxt: &Ciphertext{
					group: wrong,
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				share: shares[2],
				err:   cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				if _, err := tc.ctxt.Decrypt(group, tc.share, rand); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestCtxtVerify(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(t, typ)
		_, pk, _, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		ctxt, err := Encrypt(pk, msg, label, rand)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		for _, tc := range []struct {
			name string
			ctxt *Ciphertext
			err  error
		}{
			{
				name: "OK",
				ctxt: ctxt,
			},
			{
				name: "wrong group",
				ctxt: &Ciphertext{
					group: nist.NewBlakeSHA256QR512(),
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken C",
				ctxt: &Ciphertext{
					group: group,
					c:     []byte("broken"),
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken Label",
				ctxt: &Ciphertext{
					group: group,
					c:     ctxt.c,
					label: []byte("label"),
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken U",
				ctxt: &Ciphertext{
					group: group,
					c:     ctxt.c,
					label: ctxt.label,
					u:     group.Point().Pick(rand),
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken U_bar",
				ctxt: &Ciphertext{
					group: group,
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: group.Point().Pick(rand),
					e:     ctxt.e,
					f:     ctxt.f,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken E",
				ctxt: &Ciphertext{
					group: group,
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     group.Scalar().Pick(rand),
					f:     ctxt.f,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken F",
				ctxt: &Ciphertext{
					group: group,
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     group.Scalar().Pick(rand),
				},
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				if err := tc.ctxt.Verify(pk); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestCheckEi(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(t, typ)
		_, pk, shares, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		ctxt, err := Encrypt(pk, msg, label, rand)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		ds, err := ctxt.Decrypt(group, shares[2], rand)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		for _, tc := range []struct {
			name  string
			ctxt  *Ciphertext
			share *DecryptionShare
			err   error
		}{
			{
				name:  "OK",
				ctxt:  ctxt,
				share: ds,
			},
			{
				name: "broken U",
				ctxt: &Ciphertext{
					c:     ctxt.c,
					label: ctxt.label,
					u:     group.Point().Pick(rand),
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				share: ds,
				err:   cmpopts.AnyError,
			},
			{
				name: "out of band index",
				ctxt: ctxt,
				share: &DecryptionShare{
					index: 10,
					u_i:   ds.u_i,
					e_i:   ds.e_i,
					f_i:   ds.f_i,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken U",
				ctxt: ctxt,
				share: &DecryptionShare{
					index: ds.index,
					u_i:   group.Point().Pick(rand),
					e_i:   ds.e_i,
					f_i:   ds.f_i,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken E",
				ctxt: ctxt,
				share: &DecryptionShare{
					index: ds.index,
					u_i:   ds.u_i,
					e_i:   group.Scalar().Pick(rand),
					f_i:   ds.f_i,
				},
				err: cmpopts.AnyError,
			},
			{
				name: "broken F",
				ctxt: ctxt,
				share: &DecryptionShare{
					index: ds.index,
					u_i:   ds.u_i,
					e_i:   ds.e_i,
					f_i:   group.Scalar().Pick(rand),
				},
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				if err := checkEi(pk, tc.ctxt, tc.share); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestVerifyShare(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(t, typ)
		_, pk, shares, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		_, pkWrong, _, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		wrong := nist.NewBlakeSHA256QR512()
		ctxt, err := Encrypt(pk, msg, label, rand)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		ds, err := ctxt.Decrypt(group, shares[0], rand)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		for _, tc := range []struct {
			name  string
			pk    *PublicKey
			ctxt  *Ciphertext
			share *DecryptionShare
			err   error
		}{
			{
				name:  "OK",
				pk:    pk,
				ctxt:  ctxt,
				share: ds,
			},
			{
				name:  "wrong pk",
				pk:    pkWrong,
				ctxt:  ctxt,
				share: ds,
				err:   cmpopts.AnyError,
			},
			{
				name: "broken ctxt",
				pk:   pk,
				ctxt: &Ciphertext{
					group: group,
					c:     ctxt.c,
					label: ctxt.label,
					u:     group.Point().Pick(rand),
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				share: ds,
				err:   cmpopts.AnyError,
			},
			{
				name: "wrong ctxt group",
				pk:   pk,
				ctxt: &Ciphertext{
					group: wrong,
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				share: ds,
				err:   cmpopts.AnyError,
			},
			{
				name: "broken decryption share",
				pk:   pk,
				ctxt: ctxt,
				share: &DecryptionShare{
					group: group,
					index: ds.index,
					u_i:   ds.u_i,
					e_i:   ds.e_i,
					f_i:   group.Scalar().Pick(rand),
				},
				err: cmpopts.AnyError,
			},
			{
				name: "wrong share group",
				pk:   pk,
				ctxt: ctxt,
				share: &DecryptionShare{
					group: wrong,
					index: ds.index,
					u_i:   ds.u_i,
					e_i:   ds.e_i,
					f_i:   ds.f_i,
				},
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				if err := VerifyShare(tc.pk, tc.ctxt, tc.share); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestCombineShares(t *testing.T) {
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(t, typ)
		_, pk, shares, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		wrong := nist.NewBlakeSHA256QR512()
		_, pkWrong, _, err := GenerateKeys(group, nil, 3, 5, rand)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		pkWrong.group = wrong
		ctxt, err := Encrypt(pk, msg, label, rand)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		decShares := make([]*DecryptionShare, 5)
		for i := range shares {
			ds, err := ctxt.Decrypt(group, shares[i], rand)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			decShares[i] = ds
		}
		for _, tc := range []struct {
			name   string
			ctxt   *Ciphertext
			shares []*DecryptionShare
			k      int
			n      int
			err    error
		}{
			{
				name:   "OK (all shares)",
				ctxt:   ctxt,
				shares: decShares,
				k:      3,
				n:      5,
			},
			{
				name:   "OK (min shares)",
				ctxt:   ctxt,
				shares: decShares[:3],
				k:      3,
				n:      5,
			},
			{
				name:   "OK (reordered shares)",
				ctxt:   ctxt,
				shares: []*DecryptionShare{decShares[4], decShares[3], decShares[0]},
				k:      3,
				n:      5,
			},
			{
				name:   "Replayed shares",
				ctxt:   ctxt,
				shares: []*DecryptionShare{decShares[4], decShares[3], decShares[4]},
				k:      3,
				n:      5,
				err:    cmpopts.AnyError,
			},
			{
				name:   "not enough",
				ctxt:   ctxt,
				shares: decShares[:2],
				k:      3,
				n:      5,
				err:    cmpopts.AnyError,
			},
			{
				name: "wrong ctxt group",
				ctxt: &Ciphertext{
					group: wrong,
					c:     ctxt.c,
					label: ctxt.label,
					u:     ctxt.u,
					u_bar: ctxt.u_bar,
					e:     ctxt.e,
					f:     ctxt.f,
				},
				shares: decShares[:3],
				k:      3,
				n:      5,
				err:    cmpopts.AnyError,
			},
			{
				name: "wrong share group",
				ctxt: ctxt,
				shares: []*DecryptionShare{{
					group: wrong,
					index: decShares[4].index,
					u_i:   decShares[4].u_i,
					e_i:   decShares[4].e_i,
					f_i:   decShares[4].f_i,
				}},
				k:   1,
				n:   5,
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				out, err := tc.ctxt.CombineShares(group, tc.shares, tc.k, tc.n)
				if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("err=%v, want=%v", err, tc.err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(msg, out); diff != "" {
					t.Errorf("original/decrypted message diff: %v", diff)
				}
			})
		}
	}
}

func TestParseGroup(t *testing.T) {
	for _, tc := range []struct {
		group string
		err   error
	}{
		{
			group: nist.NewBlakeSHA256P256().String(),
		},
		{
			group: "wrong",
			err:   cmpopts.AnyError,
		},
	} {
		t.Run(fmt.Sprintf("group=%v", tc.group), func(t *testing.T) {
			if _, err := parseGroup(tc.group); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Errorf("got err=%v, want=%v", err, tc.err)
			}
		})
	}
}

func TestPublicKeyUnmarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		point, err := g.Point().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		for _, tc := range []struct {
			name string
			raw  []byte
			err  error
		}{
			{
				name: "ok",
				raw: toJSON(t, &publicKeyRaw{
					Group:  typ,
					G_bar:  point,
					H:      point,
					HArray: [][]byte{point},
				}),
			},
			{
				name: "broken",
				raw:  []byte("broken"),
				err:  cmpopts.AnyError,
			},
			{
				name: "wrong group",
				raw: toJSON(t, &publicKeyRaw{
					Group: "wrong",
					G_bar: point,
					H:     point,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong G",
				raw: toJSON(t, &publicKeyRaw{
					Group: typ,
					G_bar: []byte("broken"),
					H:     point,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong H",
				raw: toJSON(t, &publicKeyRaw{
					Group: typ,
					G_bar: point,
					H:     []byte("broken"),
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong HArray",
				raw: toJSON(t, &publicKeyRaw{
					Group:  typ,
					G_bar:  point,
					H:      point,
					HArray: [][]byte{[]byte("wrong")},
				}),
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				var pk PublicKey
				if err := pk.Unmarshal(tc.raw); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("got err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestPublicKeyMarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		for i, want := range []*PublicKey{
			{
				group: g,
				g_bar: g.Point().Pick(r),
				h:     g.Point().Pick(r),
			},
			{
				group:  g,
				g_bar:  g.Point().Pick(r),
				h:      g.Point().Pick(r),
				hArray: []kyber.Point{g.Point().Pick(r)},
			},
			{
				group:  g,
				g_bar:  g.Point().Pick(r),
				h:      g.Point().Pick(r),
				hArray: []kyber.Point{g.Point().Pick(r), g.Point().Pick(r), g.Point().Pick(r)},
			},
		} {
			t.Run(fmt.Sprintf("i=%d group=%v", i, typ), func(t *testing.T) {
				b, err := want.Marshal()
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
				var got PublicKey
				if err := got.Unmarshal(b); err != nil {
					t.Fatalf("Unmarshal: %v", err)
				}
				if !got.Equal(want) {
					t.Error("public keys not equal")
				}
			})
		}
	}
}

func TestCiphertextMarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		want := &Ciphertext{
			group: g,
			c:     []byte("some c"),
			label: []byte("some label"),
			u:     g.Point().Pick(r),
			u_bar: g.Point().Pick(r),
			e:     g.Scalar().Pick(r),
			f:     g.Scalar().Pick(r),
		}
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var got Ciphertext
		if err := got.Unmarshal(b); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !got.Equal(want) {
			t.Errorf("different ciphertexts")
		}
	}
}

func TestCiphertextUnmarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		point, err := g.Point().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("point.MarshalBinary: %v", err)
		}
		scalar, err := g.Scalar().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("scalar.MarshalBinary: %v", err)
		}
		tmp := g.Scalar().Pick(r)
		e, err := tmp.MarshalBinary()
		if err != nil {
			t.Fatalf("e.MarshalBinary: %v", err)
		}

		for _, tc := range []struct {
			name string
			raw  []byte
			err  error
		}{
			{
				name: "ok",
				raw: toJSON(t, &ciphertextRaw{
					Group: g.String(),
					C:     []byte("some c"),
					Label: []byte("some label"),
					U:     point,
					U_bar: point,
					E:     e,
					F:     scalar,
				}),
			},
			{
				name: "broken",
				raw:  []byte("broken"),
				err:  cmpopts.AnyError,
			},
			{
				name: "wrong group",
				raw: toJSON(t, &ciphertextRaw{
					Group: "wrong",
					C:     []byte("some c"),
					Label: []byte("some label"),
					U:     point,
					U_bar: point,
					E:     e,
					F:     scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong E",
				raw: toJSON(t, &ciphertextRaw{
					Group: g.String(),
					C:     []byte("some c"),
					Label: []byte("some label"),
					U:     point,
					U_bar: point,
					E:     []byte("broken"),
					F:     scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong U",
				raw: toJSON(t, &ciphertextRaw{
					Group: g.String(),
					C:     []byte("some c"),
					Label: []byte("some label"),
					U:     []byte("123"),
					U_bar: point,
					E:     e,
					F:     scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong Ubar",
				raw: toJSON(t, &ciphertextRaw{
					Group: g.String(),
					C:     []byte("some c"),
					Label: []byte("some label"),
					U:     point,
					U_bar: []byte("123"),
					E:     e,
					F:     scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "wrong F",
				raw: toJSON(t, &ciphertextRaw{
					Group: g.String(),
					C:     []byte("some c"),
					Label: []byte("some label"),
					U:     point,
					U_bar: point,
					E:     e,
					F:     []byte("123"),
				}),
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				var c Ciphertext
				if err := c.Unmarshal(tc.raw); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("got err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestMasterSecretMarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		want := &MasterSecret{
			group: g,
			s:     g.Scalar().Pick(r),
		}
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var got MasterSecret
		if err := got.Unmarshal(b); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.group.String() != want.group.String() {
			t.Errorf("got group=%v, want=%v", got.group, want.group)
		}
		if !got.s.Equal(want.s) {
			t.Errorf("got s=%v, want=%v", got.s, want.s)
		}
	}
}

func TestMasterSecretUnmarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		s, err := g.Scalar().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		for _, tc := range []struct {
			name string
			raw  []byte
			err  error
		}{
			{
				name: "ok",
				raw: toJSON(t, &masterSecretRaw{
					Group: g.String(),
					S:     s,
				}),
			},
			{
				name: "broken",
				raw:  []byte("broken"),
				err:  cmpopts.AnyError,
			},
			{
				name: "broken group",
				raw: toJSON(t, &masterSecretRaw{
					Group: "broken",
					S:     s,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "broken s",
				raw: toJSON(t, &masterSecretRaw{
					Group: g.String(),
					S:     []byte("broken"),
				}),
				err: cmpopts.AnyError,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var ms MasterSecret
				if err := ms.Unmarshal(tc.raw); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("got err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestDecryptionShareMarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		want := &DecryptionShare{
			group: g,
			index: 123,
			u_i:   g.Point().Pick(r),
			e_i:   g.Scalar().Pick(r),
			f_i:   g.Scalar().Pick(r),
		}
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var got DecryptionShare
		if err := got.Unmarshal(b); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if want.group.String() != got.group.String() {
			t.Errorf("got group=%s, want=%v", got.group, want.group)
		}
		if want.index != got.index {
			t.Errorf("got index=%v, want=%v", got.index, want.index)
		}
		if d := cmp.Diff(got.e_i, want.e_i); d != "" {
			t.Errorf("got/want E_i diff=%v", d)
		}
		if !got.u_i.Equal(want.u_i) {
			t.Errorf("got U_i=%v, want=%v", got.u_i, want.u_i)
		}
		if !got.f_i.Equal(want.f_i) {
			t.Errorf("got F_i=%v, want=%v", got.f_i, want.f_i)
		}
	}
}

func TestDecryptionShareUnmarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		point, err := g.Point().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("point.MarshalBinary: %v", err)
		}
		scalar, err := g.Scalar().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("scalar.MarshalBinary: %v", err)
		}
		tmp := g.Scalar().Pick(r)
		e, err := tmp.MarshalBinary()
		if err != nil {
			t.Fatalf("e.MarshalBinary: %v", err)
		}
		for _, tc := range []struct {
			name string
			raw  []byte
			err  error
		}{
			{
				name: "ok",
				raw: toJSON(t, &decryptionShareRaw{
					Group: g.String(),
					Index: 123,
					U_i:   point,
					E_i:   e,
					F_i:   scalar,
				}),
			},
			{
				name: "broken",
				raw:  []byte("broken"),
				err:  cmpopts.AnyError,
			},
			{
				name: "broken group",
				raw: toJSON(t, &decryptionShareRaw{
					Group: "wrong",
					Index: 123,
					U_i:   point,
					E_i:   e,
					F_i:   scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "broken E",
				raw: toJSON(t, &decryptionShareRaw{
					Group: g.String(),
					Index: 123,
					U_i:   point,
					E_i:   []byte("broken"),
					F_i:   scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "broken Ui",
				raw: toJSON(t, &decryptionShareRaw{
					Group: g.String(),
					Index: 123,
					U_i:   []byte("broken"),
					E_i:   e,
					F_i:   scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "broken Fi",
				raw: toJSON(t, &decryptionShareRaw{
					Group: g.String(),
					Index: 123,
					U_i:   point,
					E_i:   e,
					F_i:   []byte("broken scalar"),
				}),
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				var ds DecryptionShare
				if err := ds.Unmarshal(tc.raw); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("got err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func TestPrivateShareMarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		want := &PrivateShare{
			group: g,
			index: 123,
			v:     g.Scalar().Pick(r),
		}
		data, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		got := &PrivateShare{}
		if err := got.Unmarshal(data); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if want.group.String() != got.group.String() {
			t.Errorf("got group=%s, want=%v", got.group, want.group)
		}
		if !got.v.Equal(want.v) {
			t.Errorf("got V=%v, want=%v", got.v, want.v)
		}
		if got.index != want.index {
			t.Errorf("got I=%v, want=%v", got.index, want.index)
		}
	}
}

func TestPrivateShareUnmarshal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		scalar, err := g.Scalar().Pick(r).MarshalBinary()
		if err != nil {
			t.Fatalf("scalar.MarshalBinary: %v", err)
		}
		for _, tc := range []struct {
			name string
			raw  []byte
			err  error
		}{
			{
				name: "ok",
				raw: toJSON(t, &privateShareRaw{
					Group: g.String(),
					Index: 123,
					V:     scalar,
				}),
			},
			{
				name: "broken",
				raw:  []byte("broken"),
				err:  cmpopts.AnyError,
			},
			{
				name: "broken group",
				raw: toJSON(t, &privateShareRaw{
					Group: "wrong",
					Index: 123,
					V:     scalar,
				}),
				err: cmpopts.AnyError,
			},
			{
				name: "broken V",
				raw: toJSON(t, &privateShareRaw{
					Group: g.String(),
					Index: 123,
					V:     []byte("wrong"),
				}),
				err: cmpopts.AnyError,
			},
		} {
			t.Run(fmt.Sprintf("test=%q group=%v", tc.name, typ), func(t *testing.T) {
				var ps PrivateShare
				if err := ps.Unmarshal(tc.raw); !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Errorf("got err=%v, want=%v", err, tc.err)
				}
			})
		}
	}
}

func BenchmarkAll(b *testing.B) {
	for _, tc := range []struct {
		k int
		n int
	}{{k: 3, n: 5}, {k: 4, n: 7}, {k: 6, n: 10}, {k: 8, n: 15}} {
		for _, typ := range supportedGroups {
			// setup and validity checks
			group, rand, msg, label := params(b, typ)
			_, pk, shares, err := GenerateKeys(group, nil, tc.k, tc.n, rand)
			if err != nil {
				b.Fatalf("GenerateKeys: %v", err)
			}
			ctxt, err := Encrypt(pk, msg, label, rand)
			if err != nil {
				b.Fatalf("Encrypt: %v", err)
			}
			decShares := make([]*DecryptionShare, tc.n)
			for i := range shares {
				ds, err := ctxt.Decrypt(group, shares[i], rand)
				if err != nil {
					b.Fatalf("Decrypt: %v", err)
				}
				decShares[i] = ds
				err = VerifyShare(pk, ctxt, ds)
				if err != nil {
					b.Fatalf("VerifyShare: %v", err)
				}
			}
			out, err := ctxt.CombineShares(group, decShares[:tc.k], tc.k, tc.n)
			if err != nil {
				b.Fatalf("CombineShares: %v", err)
			}
			if diff := cmp.Diff(msg, out); diff != "" {
				b.Fatalf("original/decrypted message diff: %v", diff)
			}
			// run actual benchmarks
			b.Run(fmt.Sprintf("%v %d out of %d Generate", typ, tc.k, tc.n), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					GenerateKeys(group, nil, tc.k, tc.n, rand)
				}
			})
			b.Run(fmt.Sprintf("%v %d out of %d Encrypt", typ, tc.k, tc.n), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					Encrypt(pk, msg, label, rand)
				}
			})
			b.Run(fmt.Sprintf("%v %d out of %d Decrypt", typ, tc.k, tc.n), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					ctxt.Decrypt(group, shares[i%len(shares)], rand)
				}
			})
			b.Run(fmt.Sprintf("%v %d out of %d VerifyShare", typ, tc.k, tc.n), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					VerifyShare(pk, ctxt, decShares[i%len(decShares)])
				}
			})
			b.Run(fmt.Sprintf("%v %d out of %d CombineShares", typ, tc.k, tc.n), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					ctxt.CombineShares(group, decShares[:tc.k], tc.k, tc.n)
				}
			})
		}
	}
}

func BenchmarkEC(b *testing.B) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(b, typ)
		p := g.Point().Pick(r)
		q := g.Point().Pick(r)
		s := g.Scalar().Pick(r)
		b.Run(fmt.Sprintf("%v Add", typ), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.Point().Add(p, q)
			}
		})
		b.Run(fmt.Sprintf("%v Mul", typ), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.Point().Mul(s, p)
			}
		})
		b.Run(fmt.Sprintf("%v Sub", typ), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.Point().Sub(p, q)
			}
		})
	}
}

func BenchmarkChecks(b *testing.B) {
	for _, typ := range supportedGroups {
		group, rand, msg, label := params(b, typ)
		_, pk, shares, err := GenerateKeys(group, nil, 1, 1, rand)
		if err != nil {
			b.Fatalf("GenerateKeys: %v", err)
		}
		ctxt, err := Encrypt(pk, msg, label, rand)
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
		decShares := make([]*DecryptionShare, 1)
		for i := range shares {
			ds, err := ctxt.Decrypt(group, shares[i], rand)
			if err != nil {
				b.Fatalf("Decrypt: %v", err)
			}
			decShares[i] = ds
			err = VerifyShare(pk, ctxt, ds)
			if err != nil {
				b.Fatalf("VerifyShare: %v", err)
			}
		}

		b.Run(fmt.Sprintf("%v ctxt.Verify", typ), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := ctxt.Verify(pk); err != nil {
					b.Fatalf("checkE: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("%v checkEi", typ), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := checkEi(pk, ctxt, decShares[0]); err != nil {
					b.Fatalf("checkEi: %v", err)
				}
			}
		})
	}
}

func TestRedeal(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		ms, pk, _, err := GenerateKeys(g, nil, 2, 5, r)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		for _, tc := range []struct {
			name string
			ms   *MasterSecret
			k, n int
			err  error
		}{
			{
				name: "ok",
				k:    2,
				n:    5,
				ms:   ms,
			},
			{
				name: "different sizes",
				k:    1,
				n:    7,
				ms:   ms,
			},
			{
				name: "nil ms",
				k:    2,
				n:    5,
				err:  cmpopts.AnyError,
			},
			{
				name: "wrong ms",
				k:    2,
				n:    5,
				ms: &MasterSecret{
					group: nist.NewBlakeSHA256QR512(),
					s:     ms.s,
				},
				err: cmpopts.AnyError,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, shares, err := Redeal(pk, tc.ms, tc.k, tc.n, r)
				if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
					t.Fatalf("err=%v, want=%v", err, tc.err)
				} else if err != nil {
					return
				}
				if len(shares) != tc.n {
					t.Errorf("got %d shares, want %d", len(shares), tc.n)
				}
				if got.group.String() != pk.group.String() {
					t.Errorf("got group=%v, want=%v", got.group, pk.group)
				}
				if !got.g_bar.Equal(pk.g_bar) {
					t.Errorf("got g_bar=%v, want=%v", got.g_bar, pk.g_bar)
				}
				if !got.h.Equal(pk.h) {
					t.Errorf("got h=%v, want=%v", got.h, pk.h)
				}
				if len(got.hArray) != tc.n {
					t.Errorf("got hArray len=%v, want=%v", len(got.hArray), tc.n)
				}
			})
		}
	}
}

func TestRedealNewEncryption(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		ms, pk, _, err := GenerateKeys(g, nil, 3, 5, r)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		msg := []byte("12345678901234567890123456789012")
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
				newPk, shares, err := Redeal(pk, ms, tc.k, tc.n, r)
				if err != nil {
					t.Fatalf("Redeal: %v", err)
				}
				c, err := Encrypt(newPk, msg, make([]byte, 32), r)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				ds := []*DecryptionShare{}
				for _, sh := range shares {
					d, err := c.Decrypt(newPk.group, sh, r)
					if err != nil {
						t.Fatalf("Decrypt: %v", err)
					}
					if err := VerifyShare(newPk, c, d); err != nil {
						t.Fatalf("VerifyShare: %v", err)
					}
					ds = append(ds, d)
				}
				if m, err := c.CombineShares(newPk.group, ds[:tc.k], tc.k, tc.n); err != nil {
					t.Errorf("CombineShares: %v", err)
				} else if !cmp.Equal(m, msg) {
					t.Errorf("got msg=%v, want=%v", m, msg)
				}
			})
		}
	}
}

func TestRedealOldDecryption(t *testing.T) {
	for _, typ := range supportedGroups {
		g, r, _, _ := params(t, typ)
		msg := []byte("12345678901234567890123456789012")
		ms, pk, _, err := GenerateKeys(g, nil, 3, 5, r)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		c, err := Encrypt(pk, msg, make([]byte, 32), r)
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
				newPk, shares, err := Redeal(pk, ms, tc.k, tc.n, r)
				if err != nil {
					t.Fatalf("Redeal: %v", err)
				}
				ds := []*DecryptionShare{}
				for _, sh := range shares {
					d, err := c.Decrypt(newPk.group, sh, r)
					if err != nil {
						t.Fatalf("Decrypt: %v", err)
					}
					if err := VerifyShare(newPk, c, d); err != nil {
						t.Fatalf("VerifyShare: %v", err)
					}
					ds = append(ds, d)
				}
				// try to combine w/o enough new shares
				if m, err := c.CombineShares(newPk.group, ds[:tc.k-1], tc.k-1, tc.n); err != nil {
					t.Errorf("CombineShares: %v", err)
				} else if cmp.Equal(m, msg) {
					t.Errorf("got correct message")
				}
				// now try with enough new shares
				if m, err := c.CombineShares(newPk.group, ds[:tc.k], tc.k, tc.n); err != nil {
					t.Errorf("CombineShares: %v", err)
				} else if !cmp.Equal(m, msg) {
					t.Errorf("got msg=%v, want=%v", m, msg)
				}
			})
		}
	}
}

func TestRedealReuseOldShares(t *testing.T) {
	for _, typ := range supportedGroups {
		t.Run(typ, func(t *testing.T) {
			g, r, _, _ := params(t, typ)
			ms, pk, shares, err := GenerateKeys(g, nil, 2, 3, r)
			if err != nil {
				t.Fatalf("GenerateKeys: %v", err)
			}
			newPk, _, err := Redeal(pk, ms, 2, 3, r)
			if err != nil {
				t.Fatalf("Redeal: %v", err)
			}
			c, err := Encrypt(newPk, make([]byte, 32), make([]byte, 32), r)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			ds, err := c.Decrypt(g, shares[0], r)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			// make sure old shares cannot be used for new encryptions
			if err := VerifyShare(newPk, c, ds); err == nil {
				t.Error("VerifyShare did not fail")
			}
		})
	}
}

func toJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return blob
}

type marshaler interface {
	Marshal() ([]byte, error)
}

func mustMarshal(f *testing.F, m marshaler) []byte {
	f.Helper()
	b, err := m.Marshal()
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}
	return b
}

func FuzzPrivateShareMarshal(f *testing.F) {
	for _, groupStr := range supportedGroups {
		g, err := parseGroup(groupStr)
		if err != nil {
			f.Fatalf("parseGroup: %v", err)
		}
		f.Add(mustMarshal(f, PrivateShare{
			group: g,
			index: 123,
			v:     g.Scalar().Pick(keccak.New(nil)),
		}))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var ps1, ps2 PrivateShare
		if err := ps1.Unmarshal(data); err != nil {
			t.Skip()
		}
		data1, err := ps1.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := ps2.Unmarshal(data1); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := ps2.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !reflect.DeepEqual(ps1, ps2) {
			t.Errorf("ps1=%v data1=%v ps2=%v data2=%v", ps1, data1, ps2, data2)
		}
	})
}

func FuzzPublicKeyMarshal(f *testing.F) {
	r := keccak.New(nil)
	for _, groupStr := range supportedGroups {
		g, err := parseGroup(groupStr)
		if err != nil {
			f.Fatalf("parseGroup: %v", err)
		}
		f.Add(mustMarshal(f, PublicKey{
			group: g,
			g_bar: g.Point().Pick(r),
			h:     g.Point().Pick(r),
		}))
		f.Add(mustMarshal(f, PublicKey{
			group:  g,
			g_bar:  g.Point().Pick(r),
			h:      g.Point().Pick(r),
			hArray: []kyber.Point{g.Point().Pick(r)},
		}))
		f.Add(mustMarshal(f, PublicKey{
			group:  g,
			g_bar:  g.Point().Pick(r),
			h:      g.Point().Pick(r),
			hArray: []kyber.Point{g.Point().Pick(r), g.Point().Pick(r)},
		}))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var pk1, pk2 PublicKey
		if err := pk1.Unmarshal(data); err != nil {
			t.Skip()
		}
		data1, err := pk1.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := pk2.Unmarshal(data1); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := pk2.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !pk1.Equal(&pk2) {
			t.Errorf("pk1=%v data1=%v pk2=%v data2=%v", pk1, data1, pk2, data2)
		}
	})
}

func FuzzCiphertextMarshal(f *testing.F) {
	r := keccak.New(nil)
	for _, groupStr := range supportedGroups {
		g, err := parseGroup(groupStr)
		if err != nil {
			f.Fatalf("parseGroup: %v", err)
		}
		f.Add(mustMarshal(f, Ciphertext{
			group: g,
			c:     []byte("ctxt"),
			label: []byte("label"),
			u:     g.Point().Pick(r),
			u_bar: g.Point().Pick(r),
			e:     g.Scalar().Pick(r),
			f:     g.Scalar().Pick(r),
		}))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var c1, c2 Ciphertext
		if err := c1.Unmarshal(data); err != nil {
			t.Skip()
		}
		data1, err := c1.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := c2.Unmarshal(data1); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := c2.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !c1.Equal(&c2) {
			t.Errorf("c1=%v data1=%v c2=%v data2=%v", c1, data1, c2, data2)
		}
	})
}

func FuzzDecryptionShareMarshal(f *testing.F) {
	r := keccak.New(nil)
	for _, groupStr := range supportedGroups {
		g, err := parseGroup(groupStr)
		if err != nil {
			f.Fatalf("parseGroup: %v", err)
		}
		f.Add(mustMarshal(f, DecryptionShare{
			group: g,
			index: 123,
			u_i:   g.Point().Pick(r),
			e_i:   g.Scalar().Pick(r),
			f_i:   g.Scalar().Pick(r),
		}))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var ds1, ds2 DecryptionShare
		if err := ds1.Unmarshal(data); err != nil {
			t.Skip()
		}
		data1, err := ds1.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := ds2.Unmarshal(data1); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := ds2.Marshal()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !ds1.Equal(&ds2) {
			t.Errorf("ds1=%v data1=%v ds2=%v data2=%v", ds1, data1, ds2, data2)
		}
	})
}

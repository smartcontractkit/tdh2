package share

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/smartcontractkit/tdh2/go/tdh2/internal/group"
	"github.com/smartcontractkit/tdh2/go/tdh2/internal/group/nist"
)

var groups = []group.Group{
	nist.NewP256(),
	nist.NewP384(),
	nist.NewP521(),
}

func randStream(t *testing.T) cipher.Stream {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("Read: %v", err)
	}
	return cipher.NewCTR(block, iv)
}

func pubShares(g group.Group, shares []*PriShare) []*PubShare {
	out := []*PubShare{}
	for _, s := range shares {
		out = append(out, &PubShare{
			I: s.I,
			V: g.Point().Mul(s.V, nil),
		})
	}
	return out
}

func TestRecoveryWithoutSecret(test *testing.T) {
	for _, g := range groups {
		test.Run(g.String(), func(test *testing.T) {
			n := 10
			t := n/2 + 1

			priPoly := NewPriPoly(g, t, nil, randStream(test))
			shares := priPoly.Shares(n)
			pubShares := pubShares(g, shares)

			recovered, err := RecoverCommit(g, pubShares, t, n)
			if err != nil {
				test.Fatal(err)
			}

			if !recovered.Equal(g.Point().Mul(priPoly.Secret(), nil)) {
				test.Fatal("recovered commit does not match initial value")
			}

		})
	}
}

func TestRecoveryWithSecret(test *testing.T) {
	for _, g := range groups {
		test.Run(g.String(), func(test *testing.T) {
			n := 10
			t := n/2 + 1
			s := g.Scalar().Pick(randStream(test))

			priPoly := NewPriPoly(g, t, s, randStream(test))
			if !s.Equal(priPoly.Secret()) {
				test.Fatalf("secrets not equal")
			}
			shares := priPoly.Shares(n)
			pubShares := pubShares(g, shares)

			recovered, err := RecoverCommit(g, pubShares, t, n)
			if err != nil {
				test.Fatal(err)
			}

			if !recovered.Equal(g.Point().Mul(s, nil)) {
				test.Fatal("recovered commit does not match initial value")
			}
		})
	}
}

func TestPublicRecoveryOutIndex(test *testing.T) {
	for _, g := range groups {
		test.Run(g.String(), func(test *testing.T) {
			n := 10
			t := n/2 + 1

			priPoly := NewPriPoly(g, t, nil, randStream(test))
			pubShares := pubShares(g, priPoly.Shares(n))
			comm := g.Point().Mul(priPoly.Secret(), nil)

			selected := pubShares[n-t:]
			if len(selected) != t {
				test.Fatalf("len(selected) != t")
			}
			newN := t + 1

			recovered, err := RecoverCommit(g, selected, t, newN)
			if err != nil {
				test.Fatal(err)
			}

			if !recovered.Equal(comm) {
				test.Fatal("recovered commit does not match initial value")
			}
		})
	}
}

func TestPublicRecoveryDelete(test *testing.T) {
	for _, g := range groups {
		test.Run(g.String(), func(test *testing.T) {
			n := 10
			t := n/2 + 1

			priPoly := NewPriPoly(g, t, nil, randStream(test))
			shares := pubShares(g, priPoly.Shares(n))
			comm := g.Point().Mul(priPoly.Secret(), nil)

			// Corrupt a few shares
			shares[2] = nil
			shares[5] = nil
			shares[7] = nil
			shares[8] = nil

			recovered, err := RecoverCommit(g, shares, t, n)
			if err != nil {
				test.Fatal(err)
			}

			if !recovered.Equal(comm) {
				test.Fatal("recovered commit does not match initial value")
			}
		})
	}
}

func TestPublicRecoveryDeleteFail(test *testing.T) {
	for _, g := range groups {
		test.Run(g.String(), func(test *testing.T) {
			n := 10
			t := n/2 + 1

			priPoly := NewPriPoly(g, t, nil, randStream(test))
			shares := pubShares(g, priPoly.Shares(n))

			// Corrupt one more share than acceptable
			shares[1] = nil
			shares[2] = nil
			shares[5] = nil
			shares[7] = nil
			shares[8] = nil

			_, err := RecoverCommit(g, shares, t, n)
			if err == nil {
				test.Fatal("recovered commit unexpectably")
			}
		})
	}
}

// Package tdh2easy implements an easy interface of TDH2-based hybrid encryption.
package tdh2easy

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/tdh2/go/tdh2"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

// key size used in symmetric encryption (AES). 256 bits is a higher securitylevel than provided
// by the EC group deployed, but as tdh2.InputSize is 256 bits we decided to use the same value.
const aes256KeySize = 32

// defaultGroup is the default EC group used.
var defaultGroup = nist.NewBlakeSHA256P256()

// Ciphertext encodes hybrid ciphertext.
type Ciphertext struct {
	tdh2Ctxt *tdh2.Ciphertext
	symCtxt  []byte
	nonce    []byte
}

// Decrypt returns a decryption share for the ciphertext.
func (c *Ciphertext) Decrypt(x_i *tdh2.PrivateShare) (*tdh2.DecryptionShare, error) {
	xof, err := xof()
	if err != nil {
		return nil, err
	}
	return c.tdh2Ctxt.Decrypt(defaultGroup, x_i, xof)
}

// VerifyShare checks if the share matches the ciphertext and public key.
func (c *Ciphertext) VerifyShare(pk *tdh2.PublicKey, share *tdh2.DecryptionShare) error {
	return tdh2.VerifyShare(pk, c.tdh2Ctxt, share)
}

// Aggregate decrypts the TDH2-encrypted key and using it recovers the
// symmetrically encrypted plaintext. It takes decryption shares and
// the total number of participants as the arguments.
// Ciphertext and shares MUST be verified before calling Aggregate.
func (c *Ciphertext) Aggregate(shares []*tdh2.DecryptionShare, n int) ([]byte, error) {
	key, err := c.tdh2Ctxt.CombineShares(defaultGroup, shares, len(shares), n)
	if err != nil {
		return nil, fmt.Errorf("cannot combine shares: %w", err)
	}
	if aes256KeySize != len(key) {
		return nil, fmt.Errorf("incorrect key size")
	}
	return symDecrypt(c.nonce, c.symCtxt, key)
}

// xof returns xof used for providing randomness.
func xof() (kyber.XOF, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("cannot generate seed: %w", err)
	}
	return keccak.New(seed), nil
}

type ciphertextRaw struct {
	TDH2Ctxt []byte
	SymCtxt  []byte
	Nonce    []byte
}

func (c *Ciphertext) Marshal() ([]byte, error) {
	ctxt, err := c.tdh2Ctxt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("cannot marshal TDH2 ciphertext: %w", err)
	}
	return json.Marshal(&ciphertextRaw{
		TDH2Ctxt: ctxt,
		SymCtxt:  c.symCtxt,
		Nonce:    c.nonce,
	})
}

// UnmarshalVerify unmarshals ciphertext and verifies if it matches the public key.
func (c *Ciphertext) UnmarshalVerify(data []byte, pk *tdh2.PublicKey) error {
	var raw ciphertextRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("cannot unmarshal data: %w", err)
	}
	c.symCtxt = raw.SymCtxt
	c.nonce = raw.Nonce
	c.tdh2Ctxt = &tdh2.Ciphertext{}
	if err := c.tdh2Ctxt.Unmarshal(raw.TDH2Ctxt); err != nil {
		return fmt.Errorf("cannot unmarshal TDH2 ciphertext: %w", err)
	}

	if err := c.tdh2Ctxt.Verify(pk); err != nil {
		return fmt.Errorf("tdh2 ciphertext verification: %w", err)
	}
	return nil
}

// GenerateKeys generates and returns, the master secret, public key, and private shares. It takes the
// total number of nodes n and a threshold k (the number of shares sufficient for decryption).
func GenerateKeys(k, n int) (*tdh2.MasterSecret, *tdh2.PublicKey, []*tdh2.PrivateShare, error) {
	xof, err := xof()
	if err != nil {
		return nil, nil, nil, err
	}
	return tdh2.GenerateKeys(defaultGroup, nil, k, n, xof)
}

// Redeal re-deals private shares such that new quorums can decrypt old ciphertexts.
// It takes the previous public key and master secret as well as the number of nodes
// sufficient for decrypt k, and the total number of nodes n. It returns a new public
// key and private shares. The master secret passed corresponds to the public key returned.
// The old public key can still be used for encryption but it cannot be used for share
// verification (the new key has to be used instead).
func Redeal(pk *tdh2.PublicKey, ms *tdh2.MasterSecret, k, n int) (*tdh2.PublicKey, []*tdh2.PrivateShare, error) {
	xof, err := xof()
	if err != nil {
		return nil, nil, err
	}
	return tdh2.Redeal(pk, ms, k, n, xof)
}

// Encrypt generates a fresh symmetric key, encrypts and authenticates
// the message with it, and encrypts the key using TDH2. It returns a
// struct encoding the generated ciphertexts.
func Encrypt(pk *tdh2.PublicKey, msg []byte) (*Ciphertext, error) {
	if aes256KeySize != tdh2.InputSize {
		return nil, fmt.Errorf("incorrect key size")
	}
	// generate a fresh key and encrypt the message
	key, err := symKey(tdh2.InputSize)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key: %w", err)
	}
	// for each encryption a fresh key and nonce are generated,
	// therefore the probability of nonce misuse is negligible
	symCtxt, nonce, err := symEncrypt(msg, key)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt message: %w", err)
	}

	xof, err := xof()
	if err != nil {
		return nil, err
	}
	// encrypt the key with TDH2 using empty label
	tdh2Ctxt, err := tdh2.Encrypt(pk, key, make([]byte, tdh2.InputSize), xof)
	if err != nil {
		return nil, fmt.Errorf("cannot TDH2 encrypt: %w", err)
	}
	return &Ciphertext{
		tdh2Ctxt: tdh2Ctxt,
		symCtxt:  symCtxt,
		nonce:    nonce,
	}, nil
}

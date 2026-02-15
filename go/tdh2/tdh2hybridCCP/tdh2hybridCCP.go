// Package tdh2hybridCCP implements an easy interface of TDH2-based hybrid encryption
// with a moden stream cipher ChaCha20-Poly1305.
package tdh2hybridCCP

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/tdh2/go/tdh2/lib/group/nist"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2"
	"golang.org/x/crypto/chacha20poly1305"
)

// key size used in symmetric encryption (AES replaced by ChaCha20Poly1350).
// 256 bits is a higher securitylevel than provided by the EC group deployed,
// but as tdh2.InputSize is 256 bits we decided to use the same value.
// const symKeySize = 32	// AES-256
const symKeySize = chacha20poly1305.KeySize // 32 byte

// defaultGroup is the default EC group used.
var defaultGroup = nist.NewP256()

// PrivateShare encodes TDH2 private share.
type PrivateShare struct {
	p *tdh2.PrivateShare
}

// Index returns private share index.
func (p *PrivateShare) Index() int {
	return p.p.Index()
}

func (p PrivateShare) Marshal() ([]byte, error) {
	return p.p.Marshal()
}

func (p *PrivateShare) MarshalJSON() ([]byte, error) {
	return p.Marshal()
}

func (p *PrivateShare) Unmarshal(data []byte) error {
	p.p = &tdh2.PrivateShare{}
	return p.p.Unmarshal(data)
}

func (p *PrivateShare) UnmarshalJSON(data []byte) error {
	return p.Unmarshal(data)
}

func (p *PrivateShare) Clear() {
	p.p.Clear()
}

// DecryptionShare encodes TDH2 decryption share.
type DecryptionShare struct {
	d *tdh2.DecryptionShare
}

// Index returns private share index.
func (d *DecryptionShare) Index() int {
	return d.d.Index()
}

func (d DecryptionShare) Marshal() ([]byte, error) {
	return d.d.Marshal()
}

func (d DecryptionShare) MarshalJSON() ([]byte, error) {
	return d.Marshal()
}

func (d *DecryptionShare) Unmarshal(data []byte) error {
	d.d = &tdh2.DecryptionShare{}
	return d.d.Unmarshal(data)
}

func (d *DecryptionShare) UnmarshalJSON(data []byte) error {
	return d.Unmarshal(data)
}

// PublicKey encodes TDH2 public key.
type PublicKey struct {
	p *tdh2.PublicKey
}

func (p PublicKey) Marshal() ([]byte, error) {
	return p.p.Marshal()
}

func (p *PublicKey) MarshalJSON() ([]byte, error) {
	return p.Marshal()
}

func (p *PublicKey) Unmarshal(data []byte) error {
	p.p = &tdh2.PublicKey{}
	return p.p.Unmarshal(data)
}

func (p *PublicKey) UnmarshalJSON(data []byte) error {
	return p.Unmarshal(data)
}

// MasterSecret encodes TDH2 master key.
type MasterSecret struct {
	m *tdh2.MasterSecret
}

func (m MasterSecret) Marshal() ([]byte, error) {
	return m.m.Marshal()
}

func (m MasterSecret) MarshalJSON() ([]byte, error) {
	return m.Marshal()
}

func (m *MasterSecret) Unmarshal(data []byte) error {
	m.m = &tdh2.MasterSecret{}
	return m.m.Unmarshal(data)
}

func (m MasterSecret) UnmarshalJSON(data []byte) error {
	return m.Unmarshal(data)
}

func (m *MasterSecret) Clear() {
	m.m.Clear()
}

// Ciphertext encodes hybrid ciphertext.
// ChaCha20-Poly1305 implements Authenticated Encryption with Associated
// Data (AEAD), also called Additional Authenticated Data (AAD).
// It encrypts sensitive payload data while allowing additional, authenticated
// but not encrypted metadata ("associated data") to be authenticated
// along with the ciphertext which detects any tampering (modern: fast & safe).
type Ciphertext struct {
	tdh2Ctxt *tdh2.Ciphertext
	symCtxt  []byte
	nonce    []byte
	aaData   []byte // store for verification by AEAD during decryption
	//label  [tdh2.InputSize]byte	// also included in tdh2Ctxt, redundant?
}

// Decrypt returns a decryption share for the ciphertext.
func Decrypt(c *Ciphertext, x_i *PrivateShare) (*DecryptionShare, error) {
	r, err := randStream()
	if err != nil {
		return nil, err
	}
	d, err := c.tdh2Ctxt.Decrypt(defaultGroup, x_i.p, r)
	if err != nil {
		return nil, err
	}
	return &DecryptionShare{d}, nil
}

// VerifyShare checks if the share matches the ciphertext and public key.
func VerifyShare(c *Ciphertext, pk *PublicKey, share *DecryptionShare) error {
	return tdh2.VerifyShare(pk.p, c.tdh2Ctxt, share.d)
}

// Aggregate decrypts the TDH2-encrypted key and using it recovers the
// symmetrically encrypted plaintext. It takes decryption shares and
// the total number of participants as the arguments.
// Ciphertext and shares MUST be verified before calling Aggregate,
// all the shares have to be distinct and their number has to be
// at least k (the scheme's threshold).
func Aggregate(c *Ciphertext, shares []*DecryptionShare, n int) ([]byte, error) {
	sh := []*tdh2.DecryptionShare{}
	for _, s := range shares {
		sh = append(sh, s.d)
	}
	key, err := c.tdh2Ctxt.CombineShares(defaultGroup, sh, len(sh), n)
	if err != nil {
		return nil, fmt.Errorf("cannot combine shares: %w", err)
	}
	if symKeySize != len(key) {
		return nil, fmt.Errorf("incorrect key size")
	}
	return symDecrypt(c.nonce, c.symCtxt, key, c.aaData)
}

// randStream returns a stream cipher used for providing randomness.
func randStream() (cipher.Stream, error) {
	key := make([]byte, symKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cannot generate key: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cannot generate iv: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot init aes: %w", err)
	}
	return cipher.NewCTR(block, iv), nil
}

type ciphertextRaw struct {
	TDH2Ctxt []byte
	SymCtxt  []byte
	Nonce    []byte
	AaData   []byte
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
		AaData:   c.aaData,
	})
}

// UnmarshalVerify unmarshals ciphertext and verifies if it matches the public key.
func (c *Ciphertext) UnmarshalVerify(data []byte, pk *PublicKey) error {
	var raw ciphertextRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("cannot unmarshal data: %w", err)
	}
	c.symCtxt = raw.SymCtxt
	c.nonce = raw.Nonce
	c.tdh2Ctxt = &tdh2.Ciphertext{}
	c.aaData = raw.AaData
	if err := c.tdh2Ctxt.Unmarshal(raw.TDH2Ctxt); err != nil {
		return fmt.Errorf("cannot unmarshal TDH2 ciphertext: %w", err)
	}

	if err := c.tdh2Ctxt.Verify(pk.p); err != nil {
		return fmt.Errorf("tdh2 ciphertext verification: %w", err)
	}
	return nil
}

// GenerateKeys generates and returns, the master secret, public key, and private shares. It takes the
// total number of nodes n and a threshold k (the number of shares sufficient for decryption).
func GenerateKeys(k, n int) (*MasterSecret, *PublicKey, []*PrivateShare, error) {
	r, err := randStream()
	if err != nil {
		return nil, nil, nil, err
	}
	ms, pk, sh, err := tdh2.GenerateKeys(defaultGroup, nil, k, n, r)
	if err != nil {
		return nil, nil, nil, err
	}
	shares := []*PrivateShare{}
	for i := range sh {
		shares = append(shares, &PrivateShare{sh[i]})
	}
	return &MasterSecret{ms}, &PublicKey{pk}, shares, nil
}

// Redeal re-deals private shares such that new quorums can decrypt old ciphertexts.
// It takes the previous public key and master secret as well as the number of nodes
// sufficient for decrypt k, and the total number of nodes n. It returns a new public
// key and private shares. The master secret passed corresponds to the public key returned.
// The old public key can still be used for encryption but it cannot be used for share
// verification (the new key has to be used instead).
func Redeal(pk *PublicKey, ms *MasterSecret, k, n int) (*PublicKey, []*PrivateShare, error) {
	r, err := randStream()
	if err != nil {
		return nil, nil, err
	}
	p, sh, err := tdh2.Redeal(pk.p, ms.m, k, n, r)
	if err != nil {
		return nil, nil, err
	}
	shares := []*PrivateShare{}
	for i := range sh {
		shares = append(shares, &PrivateShare{sh[i]})
	}
	return &PublicKey{p}, shares, nil
}

// Encrypt generates a fresh symmetric key, encrypts and authenticates
// the message with it, and encrypts the key using TDH2 with empty label.
// It returns a struct encoding the generated ciphertexts.
func Encrypt(pk *PublicKey, msg []byte) (*Ciphertext, error) {
	return EncryptWithLabel(pk, msg, [tdh2.InputSize]byte{})
}

// EncryptWithLabel is identical to Encrypt but allows passing a
// non-empty label from TDH2 where tdh2.InputSize = sha256.Size = 32 byte
func EncryptWithLabel(pk *PublicKey, msg []byte, label [tdh2.InputSize]byte) (*Ciphertext, error) {
	return EncryptWithLabelAndAaD(pk, msg, label, nil)
}

func EncryptWithAaD(pk *PublicKey, msg, aaData []byte) (*Ciphertext, error) {
	var emptyLabel [tdh2.InputSize]byte
	return EncryptWithLabelAndAaD(pk, msg, emptyLabel, aaData)
}

func EncryptWithLabelAndAaD(pk *PublicKey, msg []byte, label [tdh2.InputSize]byte, aaData []byte) (*Ciphertext, error) {
	if symKeySize != tdh2.InputSize {
		return nil, fmt.Errorf("incorrect key size")
	}
	// generate a fresh key and encrypt the message
	key, err := symKey(tdh2.InputSize)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key: %w", err)
	}
	// for each encryption a fresh key and nonce are generated,
	// therefore the probability of nonce misuse is negligible
	symCtxt, nonce, err := symEncrypt(msg, key, aaData)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt message: %w", err)
	}

	r, err := randStream()
	if err != nil {
		return nil, err
	}
	// encrypt the key with TDH2 using the provided label
	tdh2Ctxt, err := tdh2.Encrypt(pk.p, key, label[:], r)
	if err != nil {
		return nil, fmt.Errorf("cannot TDH2 encrypt: %w", err)
	}
	return &Ciphertext{
		tdh2Ctxt: tdh2Ctxt,
		symCtxt:  symCtxt,
		nonce:    nonce,
		aaData:   aaData,
		//label:  label,	// also included in tdh2Ctxt, redundant?
	}, nil
}

// Label returns a defensive copy of the ciphertext's TDH2 label.
func (c *Ciphertext) Label() [tdh2.InputSize]byte {
	return c.tdh2Ctxt.Label()
}

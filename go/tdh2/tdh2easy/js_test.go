package tdh2easy

import (
	"bytes"
	"encoding/base64"
	"os/exec"
	"testing"
)

const jsTestPath = "../../../js/tdh2/test/test.js"

func TestJS(t *testing.T) {
	_, pk, sh, err := GenerateKeys(2, 3)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	b, err := pk.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	cmdArgs := []string{jsTestPath, string(b)}
	cmd := exec.Command("node", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run test.js: %s", err)
	}
	pairs := bytes.Split(output, []byte("\n"))
	// it contains the last empty newline
	if len(pairs) < 3 || len(pairs)%2 == 0 {
		t.Fatalf("Incorrect script output: %v", pairs)
	}
	pairs = pairs[:len(pairs)-1]
	for i := 0; i < len(pairs)/2; i++ {
		want, err := base64.StdEncoding.DecodeString(string(pairs[2*i]))
		if err != nil {
			t.Fatalf("b64Decode: %v", err)
		}
		var c Ciphertext
		if err := c.UnmarshalVerify(pairs[2*i+1], pk); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		dec := []*DecryptionShare{}
		for _, s := range sh {
			d, err := Decrypt(&c, s)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			dec = append(dec, d)
		}
		got, err := Aggregate(&c, dec, 3)
		if err != nil {
			t.Fatalf("Aggregate: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got=%v; want=%v", got, want)
		}
	}
}

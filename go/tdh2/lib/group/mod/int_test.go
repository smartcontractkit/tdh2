package mod

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func FuzzIntMarshal(f *testing.F) {
	mods := []*big.Int{elliptic.P256().Params().N, elliptic.P384().Params().N, elliptic.P521().Params().N}
	for idx, m := range mods {
		i := NewInt64(0, m)
		b, err := i.MarshalBinary()
		if err != nil {
			f.Fatalf("MarshalBinary: %v", err)
		}
		f.Add(idx, b)
	}
	f.Fuzz(func(t *testing.T, idx int, data []byte) {
		if idx < 0 || idx >= len(mods) {
			t.Skip()
		}
		i1 := NewInt64(0, mods[idx])
		i2 := NewInt64(0, mods[idx])
		if err := i1.UnmarshalBinary(data); err != nil {
			t.Skip()
		}
		data1, err := i1.MarshalBinary()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := i2.UnmarshalBinary(data1); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := i2.MarshalBinary()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !i1.Equal(i2) {
			t.Errorf("ps1=%v data1=%v ps2=%v data2=%v", i1, data1, i2, data2)
		}
	})
}

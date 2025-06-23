package nist

import (
	"bytes"
	"testing"

	"github.com/smartcontractkit/tdh2/go/tdh2/lib/group"
	"github.com/smartcontractkit/tdh2/go/tdh2/lib/group/test"
)

var benchmarks = []*test.GroupBench{
	test.NewGroupBench(NewP256()),
	test.NewGroupBench(NewP384()),
	test.NewGroupBench(NewP521()),
}

func TestSetBytesBE(t *testing.T) {
	for _, b := range benchmarks {
		t.Run(b.String(), func(t *testing.T) {
			s := b.G.Scalar()
			s.SetBytes([]byte{0, 1, 2, 3})
			// 010203 because initial 0 is trimmed in String(), and 03 (last byte of BE) ends up
			// in the LSB of the bigint.
			if s.String() != "010203" {
				t.Fatal("unexpected result from String():", s.String())
			}
		})
	}
}

func TestGroup(t *testing.T) {
	for _, bench := range benchmarks {
		t.Run(bench.String(), func(t *testing.T) {
			test.GroupTest(t, bench.G)
		})
	}
}

func BenchmarkScalarAdd(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarAdd(b.N) })
	}
}

func BenchmarkScalarSub(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarSub(b.N) })
	}
}

func BenchmarkScalarNeg(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarNeg(b.N) })
	}
}

func BenchmarkScalarMul(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarMul(b.N) })
	}
}

func BenchmarkScalarDiv(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarDiv(b.N) })
	}
}

func BenchmarkScalarInv(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarInv(b.N) })
	}
}

func BenchmarkScalarPick(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarPick(b.N) })
	}
}

func BenchmarkScalarEncode(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarEncode(b.N) })
	}
}

func BenchmarkScalarDecode(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.ScalarDecode(b.N) })
	}
}

func BenchmarkPointAdd(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointAdd(b.N) })
	}
}

func BenchmarkPointSub(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointSub(b.N) })
	}
}

func BenchmarkPointNeg(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointNeg(b.N) })
	}
}

func BenchmarkPointMul(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointMul(b.N) })
	}
}

func BenchmarkPointBaseMul(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointBaseMul(b.N) })
	}
}

func BenchmarkPointPick(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointPick(b.N) })
	}
}

func BenchmarkPointEncode(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointEncode(b.N) })
	}
}

func BenchmarkPointDecode(b *testing.B) {
	for _, bench := range benchmarks {
		b.Run(bench.String(), func(b *testing.B) { bench.PointDecode(b.N) })
	}
}

func FuzzCurvePointMarshal(f *testing.F) {
	groups := []group.Group{NewP256(), NewP384(), NewP521()}
	for idx, g := range groups {
		p := g.Point().Base()
		b, err := p.MarshalBinary()
		if err != nil {
			f.Fatalf("MarshalBinary: %v", err)
		}
		f.Add(idx, b)
	}
	f.Fuzz(func(t *testing.T, idx int, data []byte) {
		if idx < 0 || idx >= len(groups) {
			t.Skip()
		}
		p1 := groups[idx].Point()
		p2 := groups[idx].Point()
		if err := p1.UnmarshalBinary(data); err != nil {
			t.Skip()
		}
		data1, err := p1.MarshalBinary()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data, err)
		}
		if err := p2.UnmarshalBinary(data1); err != nil {
			t.Fatalf("Cannot unmarshal: data=%v err=%v", data1, err)
		}
		data2, err := p2.MarshalBinary()
		if err != nil {
			t.Fatalf("Cannot marshal: data=%v err=%v", data2, err)
		}
		if !bytes.Equal(data1, data2) {
			t.Errorf("data1=%v data2=%v", data1, data2)
		}
		if !p1.Equal(p2) {
			t.Errorf("ps1=%v data1=%v ps2=%v data2=%v", p1, data1, p2, data2)
		}
	})
}

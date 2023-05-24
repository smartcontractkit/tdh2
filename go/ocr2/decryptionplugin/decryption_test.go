package decryptionplugin

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2/types"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin/config"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"google.golang.org/protobuf/proto"
)

// dummyLogger implements a dummy logger for testing only.
type dummyLogger struct{}

func (l dummyLogger) Trace(msg string, fields commontypes.LogFields)    {}
func (l dummyLogger) Debug(msg string, fields commontypes.LogFields)    {}
func (l dummyLogger) Info(msg string, fields commontypes.LogFields)     {}
func (l dummyLogger) Warn(msg string, fields commontypes.LogFields)     {}
func (l dummyLogger) Error(msg string, fields commontypes.LogFields)    {}
func (l dummyLogger) Critical(msg string, fields commontypes.LogFields) {}

// queue implements the DecryptionQueuingService interface.
type queue struct {
	q   []DecryptionRequest
	res [][]byte
}

func (q *queue) GetRequests(requestCountLimit, totalBytesLimit int) []DecryptionRequest {
	stop := 0
	for i, tot := 0, 0; i < len(q.q) && i < requestCountLimit; i++ {
		tot += len(q.q[i].Ciphertext)
		if tot > totalBytesLimit {
			break
		}
		stop++
	}
	out := q.q[:stop]
	q.q = q.q[stop:]
	return out
}

func (q *queue) GetCiphertext(ciphertextId []byte) ([]byte, error) {
	for _, e := range q.q {
		if bytes.Equal(ciphertextId, e.CiphertextId) {
			return e.Ciphertext, nil
		}
	}
	return nil, ErrNotFound
}

func (q *queue) SetResult(ciphertextId, plaintext []byte) {
	q.res = append(q.res, ciphertextId)
	q.res = append(q.res, plaintext)
}

func makeConfig(t *testing.T, c *config.ReportingPluginConfig) types.ReportingPluginConfig {
	conf, err := config.EncodeReportingPluginConfig(&config.ReportingPluginConfigWrapper{
		Config: c,
	})
	if err != nil {
		t.Fatalf("EncodeReportingPluginConfig: %v", err)
	}
	return types.ReportingPluginConfig{OffchainConfig: conf}

}

func TestNewReportingPlugin(t *testing.T) {
	_, pk, sh, err := tdh2easy.GenerateKeys(1, 1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	pkRaw, err := pk.Marshal()
	if err != nil {
		if err != nil {
			t.Fatalf("pk.Marshal: %v", err)
		}
	}
	shRaw, err := sh[0].Marshal()
	if err != nil {
		if err != nil {
			t.Fatalf("sh.Marshal: %v", err)
		}
	}
	for _, tc := range []struct {
		name string
		conf types.ReportingPluginConfig
		err  error
	}{
		{
			name: "ok",
			conf: makeConfig(t, &config.ReportingPluginConfig{
				MaxQueryLengthBytes:       1,
				MaxObservationLengthBytes: 2,
				MaxReportLengthBytes:      3,
				PublicKey:                 pkRaw,
				PrivKeyShare:              shRaw,
				OracleIdToKeyIndex: []*config.OracleIDtoKeyShareIndex{
					{OracleId: 1, KeyShareIndex: 11},
					{OracleId: 2, KeyShareIndex: 22},
					{OracleId: 3, KeyShareIndex: 33},
				},
			}),
		},
		{
			name: "ok minimal",
			conf: makeConfig(t, &config.ReportingPluginConfig{
				PublicKey:    pkRaw,
				PrivKeyShare: shRaw,
			}),
		},
		{
			name: "broken privkey",
			conf: makeConfig(t, &config.ReportingPluginConfig{
				PublicKey:    pkRaw,
				PrivKeyShare: []byte("broken"),
			}),
			err: cmpopts.AnyError,
		},
		{
			name: "broken pubkey",
			conf: makeConfig(t, &config.ReportingPluginConfig{
				PublicKey:    []byte("broken"),
				PrivKeyShare: shRaw,
			}),
			err: cmpopts.AnyError,
		},
		{
			name: "overflow OracleID",
			conf: makeConfig(t, &config.ReportingPluginConfig{
				PublicKey:    pkRaw,
				PrivKeyShare: shRaw,
				OracleIdToKeyIndex: []*config.OracleIDtoKeyShareIndex{
					{OracleId: 991, KeyShareIndex: 11},
				},
			}),
			err: cmpopts.AnyError,
		},
		{
			name: "broken conf",
			conf: types.ReportingPluginConfig{
				OffchainConfig: []byte("broken"),
			},
			err: cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := DecryptionReportingPluginFactory{Logger: dummyLogger{}}
			plugin, info, err := factory.NewReportingPlugin(tc.conf)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Fatalf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			conf, err := config.DecodeReportingPluginConfig(tc.conf.OffchainConfig)
			if err != nil {
				t.Fatalf("DecodeReportingPluginConfig: %v", err)
			}
			if a, b := info.Limits.MaxQueryLength, int(conf.Config.MaxQueryLengthBytes); a != b {
				t.Errorf("info.Limits.MaxQueryLength=%v, want=%v", a, b)

			}
			if a, b := info.Limits.MaxObservationLength, int(conf.Config.MaxObservationLengthBytes); a != b {
				t.Errorf("info.Limits.MaxObservationLength=%v, want=%v", a, b)
			}
			if a, b := info.Limits.MaxReportLength, int(conf.Config.MaxReportLengthBytes); a != b {
				t.Errorf("info.Limits.MaxReportLength=%v, want=%v", a, b)
			}
			p := plugin.(*decryptionPlugin)
			if a, b := len(p.oracleToKeyShare), len(conf.Config.OracleIdToKeyIndex); a != b {
				t.Errorf("oracleToKeyShare has %v entries, want %d", a, b)
			}
			for _, e := range conf.Config.OracleIdToKeyIndex {
				got, ok := p.oracleToKeyShare[commontypes.OracleID(e.OracleId)]
				if !ok {
					t.Errorf("no key share for %v", e.OracleId)
					continue
				}
				if got != int(e.KeyShareIndex) {
					t.Errorf("share index=%v, want=%v", got, int(e.KeyShareIndex))
				}
			}
		})
	}
}

func TestGetValidDecryptionShare(t *testing.T) {
	_, pk, sh, err := tdh2easy.GenerateKeys(1, 2)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	c, err := tdh2easy.Encrypt(pk, []byte("msg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ds, err := tdh2easy.Decrypt(c, sh[1])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	dsRaw, err := ds.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	c2, err := tdh2easy.Encrypt(pk, []byte("msg2"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dp := &decryptionPlugin{
		oracleToKeyShare: map[commontypes.OracleID]int{
			10:  0,
			123: 1,
		},
		publicKey: pk,
	}
	for _, tc := range []struct {
		name  string
		id    commontypes.OracleID
		c     *tdh2easy.Ciphertext
		share []byte
		err   error
	}{
		{
			name:  "ok",
			id:    123,
			c:     c,
			share: dsRaw,
		},
		{
			name:  "no oracle",
			id:    1,
			c:     c,
			share: dsRaw,
			err:   cmpopts.AnyError,
		},
		{
			name:  "wrong index",
			id:    10,
			c:     c,
			share: dsRaw,
			err:   cmpopts.AnyError,
		},
		{
			name:  "wrong share",
			id:    123,
			c:     c2,
			share: dsRaw,
			err:   cmpopts.AnyError,
		},
		{
			name:  "broken ds",
			id:    123,
			c:     c,
			share: []byte("broken"),
			err:   cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dp.getValidDecryptionShare(tc.id, tc.c, tc.share)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Fatalf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			if !reflect.DeepEqual(got, ds) {
				t.Errorf("got ds=%v, want=%v", got, ds)
			}
		})
	}

}

func TestQuery(t *testing.T) {
	_, pk, _, err := tdh2easy.GenerateKeys(1, 2)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	ctxts := []*CiphertextWithID{}
	for i := 0; i < 10; i++ {
		id := []byte(fmt.Sprintf("%d", i))
		c, err := tdh2easy.Encrypt(pk, id)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		raw, err := c.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		ctxts = append(ctxts, &CiphertextWithID{
			CiphertextId: id,
			Ciphertext:   raw,
		})
	}
	for _, tc := range []struct {
		name string
		in   []*CiphertextWithID
		want []*CiphertextWithID
	}{
		{
			name: "empty",
		},
		{
			name: "one",
			in:   ctxts[:1],
			want: ctxts[:1],
		},
		{
			name: "all",
			in:   ctxts,
			want: ctxts,
		},
		{
			name: "one wrong",
			in: append(ctxts, &CiphertextWithID{
				CiphertextId: []byte("1"),
				Ciphertext:   []byte("broken"),
			}),
			want: ctxts,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &queue{}
			for _, e := range tc.in {
				q.q = append(q.q, DecryptionRequest{
					CiphertextId: e.CiphertextId,
					Ciphertext:   e.Ciphertext,
				})
			}
			dp := &decryptionPlugin{
				logger:    dummyLogger{},
				publicKey: pk,
				specificConfig: &config.ReportingPluginConfigWrapper{
					Config: &config.ReportingPluginConfig{
						RequestCountLimit:      999,
						RequestTotalBytesLimit: 999999,
					},
				},
				decryptionQueue: q,
			}
			b, err := dp.Query(context.Background(), types.ReportTimestamp{})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			got := Query{}
			if err := proto.Unmarshal(b, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if d := cmp.Diff(got.DecryptionRequests, tc.want, cmpopts.IgnoreUnexported(CiphertextWithID{})); d != "" {
				t.Errorf("got/want diff=%v", d)
			}
		})
	}
}

func TestShouldAcceptFinalizedReport(t *testing.T) {
	r := &Report{
		ProcessedDecryptedRequests: []*ProcessedDecryptionRequest{
			{
				CiphertextId: []byte("id1"),
				Plaintext:    []byte("p1"),
			},
			{
				CiphertextId: []byte("id2"),
				Plaintext:    []byte("p2"),
			},
			{
				CiphertextId: []byte("id3"),
				Plaintext:    []byte("p3"),
			},
		},
	}
	b, err := proto.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, tc := range []struct {
		name string
		in   []byte
		want [][]byte
		err  error
	}{
		{
			name: "empty",
		},
		{
			name: "broken",
			in:   []byte("broken"),
			err:  cmpopts.AnyError,
		},
		{
			name: "ok",
			in:   b,
			want: [][]byte{[]byte("id1"), []byte("p1"), []byte("id2"), []byte("p2"), []byte("id3"), []byte("p3")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &decryptionPlugin{
				logger:          dummyLogger{},
				decryptionQueue: &queue{},
			}
			transmit, err := dp.ShouldAcceptFinalizedReport(context.Background(), types.ReportTimestamp{}, tc.in)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Fatalf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			if transmit {
				t.Errorf("ShouldAcceptFinalizedReport returned true")
			}
			q := dp.decryptionQueue.(*queue)
			if d := cmp.Diff(q.res, tc.want); d != "" {
				t.Errorf("got/want diff=%v", d)
			}
		})
	}
}

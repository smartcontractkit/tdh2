package decryptionplugin

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
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
	if bytes.Equal([]byte("please fail"), ciphertextId) {
		return nil, fmt.Errorf("some error")
	}
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
	t.Helper()
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
			}),
		},
		{
			name: "ok minimal",
			conf: makeConfig(t, &config.ReportingPluginConfig{}),
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
			factory := DecryptionReportingPluginFactory{
				Logger:       dummyLogger{},
				PublicKey:    pk,
				PrivKeyShare: sh[0],
			}
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
			if !reflect.DeepEqual(p.publicKey, pk) {
				t.Errorf("got pubkey %v, want %v", p.publicKey, pk)
			}
			if !reflect.DeepEqual(p.privKeyShare, sh[0]) {
				t.Errorf("got privkey %v, want %v", p.privKeyShare, sh[0])
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

func makeQuery(t *testing.T, c []*CiphertextWithID) []byte {
	t.Helper()
	b, err := proto.Marshal(&Query{
		DecryptionRequests: c,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

type ctxtWithId struct {
	id []byte
	c  *tdh2easy.Ciphertext
}

func TestObservation(t *testing.T) {
	_, pk, sh, err := tdh2easy.GenerateKeys(1, 2)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	q := &queue{}
	ctxts := []*ctxtWithId{}
	ctxtsRaw := []*CiphertextWithID{}
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
		ctxtsRaw = append(ctxtsRaw, &CiphertextWithID{
			CiphertextId: id,
			Ciphertext:   raw,
		})
		// add only 5 to the queue
		if i < 5 {
			q.q = append(q.q, DecryptionRequest{
				CiphertextId: id,
				Ciphertext:   raw,
			})
		}
		ctxts = append(ctxts, &ctxtWithId{
			id: id,
			c:  c,
		})
	}
	for _, tc := range []struct {
		name  string
		query []byte
		local bool
		queue DecryptionQueuingService
		err   error
		want  []*ctxtWithId
	}{
		{
			name:  "broken",
			query: []byte("broken"),
			err:   cmpopts.AnyError,
		},
		{
			name:  "empty",
			query: makeQuery(t, nil),
		},
		{
			name:  "one",
			query: makeQuery(t, ctxtsRaw[:1]),
			want:  ctxts[:1],
		},
		{
			name:  "many",
			query: makeQuery(t, ctxtsRaw),
			want:  ctxts,
		},
		{
			name:  "many locally queued",
			query: makeQuery(t, ctxtsRaw[:5]),
			local: true,
			queue: q,
			want:  ctxts[:5],
		},
		{
			name:  "some locally queued, some not found",
			query: makeQuery(t, ctxtsRaw),
			local: true,
			queue: q,
			want:  ctxts[:5],
		},
		{
			name: "queue failing",
			query: makeQuery(t, append(ctxtsRaw[:5], &CiphertextWithID{
				CiphertextId: []byte("please fail"),
				Ciphertext:   ctxtsRaw[5].Ciphertext,
			})),
			local: true,
			queue: q,
			want:  ctxts[:5],
		},
		{
			name: "queued ciphertext mismatch",
			query: makeQuery(t, append(ctxtsRaw[:4], &CiphertextWithID{
				CiphertextId: ctxtsRaw[4].CiphertextId,
				Ciphertext:   ctxtsRaw[5].Ciphertext,
			})),
			local: true,
			queue: q,
			want:  ctxts[:4],
		},
		{
			name: "broken ciphertext",
			query: makeQuery(t, append(ctxtsRaw[:3], &CiphertextWithID{
				CiphertextId: []byte("id"),
				Ciphertext:   []byte("broken"),
			})),
			err: cmpopts.AnyError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &decryptionPlugin{
				logger:       dummyLogger{},
				publicKey:    pk,
				privKeyShare: sh[1],
				specificConfig: &config.ReportingPluginConfigWrapper{
					Config: &config.ReportingPluginConfig{
						RequireLocalRequestCheck: tc.local,
					},
				},
				decryptionQueue: tc.queue,
			}
			b, err := dp.Observation(context.Background(), types.ReportTimestamp{}, tc.query)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Fatalf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			var got Observation
			if err := proto.Unmarshal(b, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if a, b := len(got.DecryptionShares), len(tc.want); a != b {
				t.Errorf("got %v dec shares, want %v", a, b)
			}
			for i := 0; i < len(got.DecryptionShares) && i < len(tc.want); i++ {
				if a, b := got.DecryptionShares[i].CiphertextId, tc.want[i].id; !bytes.Equal(a, b) {
					t.Errorf("got id=%v, want=%v", a, b)
				}
				var ds tdh2easy.DecryptionShare
				if err := ds.Unmarshal(got.DecryptionShares[i].DecryptionShare); err != nil {
					t.Errorf("Unmarshal: %v", err)
					continue
				}
				if ds.Index() != 1 {
					t.Errorf("got index=%v, want=1", ds.Index())
				}
				if err := tdh2easy.VerifyShare(tc.want[i].c, pk, &ds); err != nil {
					t.Errorf("VerifyShare id=%v err=%v", tc.want[i].id, err)
				}
			}
		})
	}
}

func makeObservations(t *testing.T, oracle2ids map[int][]string, id2shares map[string][][]byte) []types.AttributedObservation {
	t.Helper()
	var out []types.AttributedObservation
	for oracle, ids := range oracle2ids {
		decShares := []*DecryptionShareWithID{}
		for _, id := range ids {
			decShares = append(decShares, &DecryptionShareWithID{
				CiphertextId:    []byte(id),
				DecryptionShare: id2shares[id][oracle],
			})
		}
		ob, err := proto.Marshal(&Observation{
			DecryptionShares: decShares,
		})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		out = append(out, types.AttributedObservation{
			Observer:    commontypes.OracleID(oracle),
			Observation: ob,
		})
	}
	return out
}

func TestReport(t *testing.T) {
	_, pk, sh, err := tdh2easy.GenerateKeys(3, 5)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	want := []*ProcessedDecryptionRequest{}
	ctxts := []*CiphertextWithID{}
	shares := map[string][][]byte{}
	// generate id-plaintext pairs, "id0"->"0", "id1"->"1", "id2"->"2"
	for i := 0; i < 3; i++ {
		id := []byte(fmt.Sprintf("id%d", i))
		plain := []byte(fmt.Sprintf("%d", i))
		c, err := tdh2easy.Encrypt(pk, plain)
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
		want = append(want, &ProcessedDecryptionRequest{
			CiphertextId: id,
			Plaintext:    plain,
		})
		for _, s := range sh {
			ds, err := tdh2easy.Decrypt(c, s)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			b, err := ds.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			shares[string(id)] = append(shares[string(id)], b)
		}
	}
	for _, tc := range []struct {
		name          string
		query         []byte
		obs           []types.AttributedObservation
		err           error
		wantProcessed bool
		want          []*ProcessedDecryptionRequest
	}{
		{
			name:  "empty",
			query: makeQuery(t, nil),
		},
		{
			name:  "broken query",
			query: []byte("broken"),
			err:   cmpopts.AnyError,
		},
		{
			name: "broken ciphertext",
			query: makeQuery(t, append(ctxts, &CiphertextWithID{
				CiphertextId: []byte("id"),
				Ciphertext:   []byte("broken"),
			})),
			err: cmpopts.AnyError,
		},
		{
			name:  "nothing processed (no shares)",
			query: makeQuery(t, ctxts),
		},
		{
			name:  "nothing processed (no enough shares)",
			query: makeQuery(t, ctxts),
			obs: makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
			}, shares),
		},
		{
			name:  "one processed",
			query: makeQuery(t, ctxts[:1]),
			obs: makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
				2: {"id0", "id1", "id2"},
			}, shares),
			wantProcessed: true,
			want:          want[:1],
		},
		{
			name:  "two processed",
			query: makeQuery(t, ctxts),
			obs: makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
				2: {"id0", "id1"},
			}, shares),
			wantProcessed: true,
			want:          want[:2],
		},
		{
			name:  "all processed",
			query: makeQuery(t, ctxts),
			obs: makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
				2: {"id0", "id1", "id2"},
			}, shares),
			wantProcessed: true,
			want:          want,
		},
		{
			name:  "all processed, more shares than needed",
			query: makeQuery(t, ctxts),
			obs: makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
				2: {"id0", "id1", "id2"},
				3: {"id0", "id1", "id2"},
			}, shares),
			wantProcessed: true,
			want:          want,
		},
		{
			name:  "nothing processed (wrong oracle-index mapping)",
			query: makeQuery(t, ctxts),
			obs: makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
				4: {"id0", "id1", "id2"},
			}, shares),
		},
		{
			name:  "all processed, one broken obs",
			query: makeQuery(t, ctxts),
			obs: append(makeObservations(t, map[int][]string{
				0: {"id0", "id1", "id2"},
				1: {"id0", "id1", "id2"},
				2: {"id0", "id1", "id2"},
			}, shares), types.AttributedObservation{
				Observer:    4,
				Observation: []byte("broken"),
			}),
			wantProcessed: true,
			want:          want,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &decryptionPlugin{
				logger:    dummyLogger{},
				publicKey: pk,
				genericConfig: &types.ReportingPluginConfig{
					F: 2,
				},
				oracleToKeyShare: map[commontypes.OracleID]int{
					0: 0,
					1: 1,
					2: 2,
					3: 3,
					4: 5, // wrong mapping
				},
			}
			processed, reportBytes, err := dp.Report(context.Background(), types.ReportTimestamp{}, tc.query, tc.obs)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Fatalf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			if processed != tc.wantProcessed {
				t.Errorf("got processed=%v, want=%v", processed, tc.wantProcessed)
			}
			var report Report
			if err := proto.Unmarshal(reportBytes, &report); err != nil {
				t.Errorf("Unmarshal: %v", err)
			}
			// make sure processed requests are sorted before comparison
			got := report.ProcessedDecryptedRequests
			sort.Slice(got, func(i, j int) bool {
				return string(got[i].CiphertextId) < string(got[j].CiphertextId)
			})
			if d := cmp.Diff(got, tc.want, cmpopts.IgnoreUnexported(ProcessedDecryptionRequest{})); d != "" {
				t.Errorf("got/want diff=%v", d)
			}
		})
	}
}

package decryptionplugin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2/types"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin/config"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
)

type dummyLogger struct{}

func (l dummyLogger) Trace(msg string, fields commontypes.LogFields)    {}
func (l dummyLogger) Debug(msg string, fields commontypes.LogFields)    {}
func (l dummyLogger) Info(msg string, fields commontypes.LogFields)     {}
func (l dummyLogger) Warn(msg string, fields commontypes.LogFields)     {}
func (l dummyLogger) Error(msg string, fields commontypes.LogFields)    {}
func (l dummyLogger) Critical(msg string, fields commontypes.LogFields) {}

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

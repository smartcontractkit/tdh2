package decryptionplugin

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smartcontractkit/libocr/offchainreporting2/types"
)

func TestNewReportingPlugin(t *testing.T) {
	factory := DecryptionReportingPluginFactory{
		// Logger: logger.TestLogger(t),
	}
	for _, tc := range []struct {
		name   string
		conf   types.ReportingPluginConfig
		plugin types.ReportingPlugin
		info   types.ReportingPluginInfo
		err    error
	}{
		{
			name: "ok",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plugin, info, err := factory.NewReportingPlugin(tc.conf)
			if !cmp.Equal(err, tc.err, cmpopts.EquateErrors()) {
				t.Fatalf("err=%v, want=%v", err, tc.err)
			} else if err != nil {
				return
			}
			if !reflect.DeepEqual(plugin, tc.plugin) {
				t.Errorf("plugin=%v, want=%v", plugin, tc.plugin)
			}
			if !reflect.DeepEqual(info, tc.info) {
				t.Errorf("info=%v, want=%v", info, tc.info)
			}
		})
	}

}

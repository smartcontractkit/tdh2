package config

import (
	"fmt"
	"math"

	"github.com/smartcontractkit/libocr/commontypes"
	"google.golang.org/protobuf/proto"
)

// This config is stored in the Oracle contract (set via SetConfig()).
// Every SetConfig() call reloads the reporting plugin (DirectRequestReportingPluginFactory.NewReportingPlugin())
type ReportingPluginConfigWrapper struct {
	Config *ReportingPluginConfig
}

func DecodeReportingPluginConfig(raw []byte) (*ReportingPluginConfigWrapper, error) {
	configProto := &ReportingPluginConfig{}
	err := proto.Unmarshal(raw, configProto)
	if err != nil {
		return nil, err
	}
	return &ReportingPluginConfigWrapper{Config: configProto}, nil
}

func EncodeReportingPluginConfig(rpConfig *ReportingPluginConfigWrapper) ([]byte, error) {
	return proto.Marshal(rpConfig.Config)
}

func EncodeOracleIDtoKeyShareIndex(oracleID commontypes.OracleID, keyShareIndex int) *OracleIDtoKeyShareIndex {
	return &OracleIDtoKeyShareIndex{
		OracleID:      uint32(oracleID),
		KeyShareIndex: uint32(keyShareIndex),
	}
}

func DecodeOracleIDtoKeyShareIndex(oracleIDtoKeyShareIndex *OracleIDtoKeyShareIndex) (commontypes.OracleID, int, error) {
	if oracleIDtoKeyShareIndex.OracleID > math.MaxUint8 {
		return 0, 0, fmt.Errorf("oracleID is larger than MAX_UINT8")
	}
	return commontypes.OracleID(oracleIDtoKeyShareIndex.OracleID), int(oracleIDtoKeyShareIndex.KeyShareIndex), nil
}

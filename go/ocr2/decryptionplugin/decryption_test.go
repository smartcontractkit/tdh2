package decryptionplugin_test

import (
	"errors"
	"testing"

	"github.com/smartcontractkit/libocr/offchainreporting2/types"
	"github.com/smartcontractkit/libocr/ragep2p/loggers"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin/config"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin/config/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewReportingPlugin_CustomConfigParser(t *testing.T) {
	customParser := mocks.NewConfigParser(t)
	factory := decryptionplugin.DecryptionReportingPluginFactory{
		ConfigParser: customParser,
		Logger:       loggers.MakeLogrusLogger(),
	}

	customParser.On("ParseConfig", mock.Anything).Return(&config.ReportingPluginConfigWrapper{}, nil).Once()
	_, _, err := factory.NewReportingPlugin(types.ReportingPluginConfig{})
	require.NoError(t, err)

	customParser.On("ParseConfig", mock.Anything).Return(nil, errors.New("error")).Once()
	_, _, err = factory.NewReportingPlugin(types.ReportingPluginConfig{})
	require.Error(t, err)
}

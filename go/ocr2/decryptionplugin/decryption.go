package decryptionplugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2/types"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin/config"
	"github.com/smartcontractkit/tdh2/go/tdh2easy"
	"google.golang.org/protobuf/proto"
)

type DecryptionReportingPluginFactory struct {
	DecryptionQueue  DecryptionQueuingService
	PublicKey        *tdh2easy.PublicKey
	PrivKeyShare     *tdh2easy.PrivateShare
	OracleToKeyShare map[commontypes.OracleID]int
	Logger           commontypes.Logger
}

type decryptionPlugin struct {
	logger           commontypes.Logger
	decryptionQueue  DecryptionQueuingService
	publicKey        *tdh2easy.PublicKey
	privKeyShare     *tdh2easy.PrivateShare
	oracleToKeyShare map[commontypes.OracleID]int
	genericConfig    *types.ReportingPluginConfig
	specificConfig   *config.ReportingPluginConfigWrapper
}

// NewReportingPlugin complies with ReportingPluginFactory.
func (f DecryptionReportingPluginFactory) NewReportingPlugin(rpConfig types.ReportingPluginConfig) (types.ReportingPlugin, types.ReportingPluginInfo, error) {
	pluginConfig, err := config.DecodeReportingPluginConfig(rpConfig.OffchainConfig)
	if err != nil {
		f.Logger.Error("unable to decode reporting plugin config", commontypes.LogFields{
			"configDigest": rpConfig.ConfigDigest.String(),
		})
		return nil, types.ReportingPluginInfo{}, fmt.Errorf("unalbe to decode reporting plugin config: %w", err)
	}

	info := types.ReportingPluginInfo{
		Name:          "ThresholdDecryption",
		UniqueReports: false, // Aggregating any f+1 valid decryption shares result in the same plaintext. Must match setting in OCR2Base.sol.
		// TODO calculate limits based on the maximum size of the plaintext and ciphertextID
		Limits: types.ReportingPluginLimits{
			MaxQueryLength:       int(pluginConfig.Config.GetMaxQueryLengthBytes()),
			MaxObservationLength: int(pluginConfig.Config.GetMaxObservationLengthBytes()),
			MaxReportLength:      int(pluginConfig.Config.GetMaxReportLengthBytes()),
		},
	}
	
	plugin := decryptionPlugin{
		f.Logger,
		f.DecryptionQueue,
		f.PublicKey,
		f.PrivKeyShare,
		f.OracleToKeyShare,
		&rpConfig,
		pluginConfig,
	}

	return &plugin, info, nil
}

// Query creates a query with the oldest pending decryption requests.
func (dp *decryptionPlugin) Query(ctx context.Context, ts types.ReportTimestamp) (types.Query, error) {
	dp.logger.Debug("DecryptionReporting Query: start", commontypes.LogFields{
		"epoch": ts.Epoch,
		"round": ts.Round,
	})

	decryptionRequests := dp.decryptionQueue.GetRequests(
		int(dp.specificConfig.Config.RequestCountLimit),
		int(dp.specificConfig.Config.RequestTotalBytesLimit),
	)

	queryProto := Query{}
	for _, request := range decryptionRequests {
		ciphertext := &tdh2easy.Ciphertext{}
		if err := ciphertext.UnmarshalVerify(request.Ciphertext, dp.publicKey); err != nil {
			dp.logger.Error("DecryptionReporting Query: cannot unmarshal the ciphertext, skipping it", commontypes.LogFields{
				"error":        err,
				"ciphertextID": request.CiphertextId,
			})
			continue
		}
		queryProto.DecryptionRequests = append(queryProto.GetDecryptionRequests(), &CiphertextWithID{
			CiphertextId: request.CiphertextId,
			Ciphertext:   request.Ciphertext,
		})
	}

	dp.logger.Debug("DecryptionReporting Query: end", commontypes.LogFields{
		"epoch":    ts.Epoch,
		"round":    ts.Round,
		"queryLen": len(queryProto.DecryptionRequests),
	})
	queryProtoBytes, err := proto.Marshal(&queryProto)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal query: %w", err)
	}
	return queryProtoBytes, nil
}

// Observation creates a decryption share for each request in the query.
// If dp.specificConfig.Config.LocalRequest is true, then the oracle
// only creates a decryption share for the decryption requests which it has locally.
func (dp *decryptionPlugin) Observation(ctx context.Context, ts types.ReportTimestamp, query types.Query) (types.Observation, error) {
	dp.logger.Debug("DecryptionReporting Observation: start", commontypes.LogFields{
		"epoch": ts.Epoch,
		"round": ts.Round,
	})

	queryProto := &Query{}
	if err := proto.Unmarshal(query, queryProto); err != nil {
		return nil, fmt.Errorf("cannot unmarshal query: %w", err)
	}

	observationProto := Observation{}
	for _, request := range queryProto.DecryptionRequests {
		ciphertext := &tdh2easy.Ciphertext{}
		ciphertextBytes := request.Ciphertext
		if err := ciphertext.UnmarshalVerify(ciphertextBytes, dp.publicKey); err != nil {
			dp.logger.Error("DecryptionReporting Observation: cannot unmarshal and verify the ciphertext, the leader is faulty", commontypes.LogFields{
				"error":        err,
				"ciphertextID": request.CiphertextId,
			})
			return nil, fmt.Errorf("cannot unmarshal and verify the ciphertext: %w", err)
		}
		if dp.specificConfig.Config.RequireLocalRequestCheck {
			queueCiphertextBytes, err := dp.decryptionQueue.GetCiphertext(request.CiphertextId)
			if err != nil && errors.Is(err, ErrNotFound) {
				dp.logger.Warn("DecryptionReporting Observation: cannot find ciphertext locally, skipping it", commontypes.LogFields{
					"error":        err,
					"ciphertextID": request.CiphertextId,
				})
				continue
			} else if err != nil {
				dp.logger.Error("DecryptionReporting Observation: failed when looking for ciphertext locally, skipping it", commontypes.LogFields{
					"error":        err,
					"ciphertextID": request.CiphertextId,
				})
				continue
			}
			if !bytes.Equal(queueCiphertextBytes, ciphertextBytes) {
				dp.logger.Error("DecryptionReporting Observation: local ciphertext does not match the query ciphertext, skipping it", commontypes.LogFields{
					"ciphertextID": request.CiphertextId,
				})
				continue
			}
		}

		decryptionShare, err := tdh2easy.Decrypt(ciphertext, dp.privKeyShare)
		if err != nil {
			dp.logger.Error("DecryptionReporting Observation: cannot decrypt the ciphertext", commontypes.LogFields{
				"error":        err,
				"ciphertextID": request.CiphertextId,
			})
			continue
		}
		decryptionShareBytes, err := decryptionShare.Marshal()
		if err != nil {
			dp.logger.Error("DecryptionReporting Observation: cannot marshal the decryption share, skipping it", commontypes.LogFields{
				"error":        err,
				"ciphertextID": request.CiphertextId,
			})
			continue
		}
		observationProto.DecryptionShares = append(observationProto.DecryptionShares, &DecryptionShareWithID{
			CiphertextId:    request.CiphertextId,
			DecryptionShare: decryptionShareBytes,
		})
	}

	dp.logger.Debug("DecryptionReporting Observation: end", commontypes.LogFields{
		"epoch":             ts.Epoch,
		"round":             ts.Round,
		"decryptedRequests": len(observationProto.DecryptionShares),
		"totalRequests":     len(queryProto.DecryptionRequests),
	})
	observationProtoBytes, err := proto.Marshal(&observationProto)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal observation: %w", err)
	}
	return observationProtoBytes, nil
}

// Report aggregates decryption shares from Observations to derive the plaintext.
func (dp *decryptionPlugin) Report(ctx context.Context, ts types.ReportTimestamp, query types.Query, obs []types.AttributedObservation) (bool, types.Report, error) {
	dp.logger.Debug("DecryptionReporting Report: start", commontypes.LogFields{
		"epoch":         ts.Epoch,
		"round":         ts.Round,
		"nObservations": len(obs),
	})

	queryProto := &Query{}
	if err := proto.Unmarshal(query, queryProto); err != nil {
		return false, nil, fmt.Errorf("cannot unmarshal query: %w ", err)
	}
	ciphertexts := make(map[string]*tdh2easy.Ciphertext)
	for _, request := range queryProto.DecryptionRequests {
		ciphertext := &tdh2easy.Ciphertext{}
		if err := ciphertext.UnmarshalVerify(request.Ciphertext, dp.publicKey); err != nil {
			dp.logger.Error("DecryptionReporting Report: cannot unmarshal and verify the ciphertext, the leader is faulty", commontypes.LogFields{
				"error":        err,
				"ciphertextID": request.CiphertextId,
			})
			return false, nil, fmt.Errorf("cannot unmarshal and verify the ciphertext: %w", err)
		}
		ciphertexts[string(request.CiphertextId)] = ciphertext
	}

	fPlusOne := dp.genericConfig.F + 1
	validDecryptionShares := make(map[string][]*tdh2easy.DecryptionShare)
	for _, ob := range obs {
		observationProto := &Observation{}
		if err := proto.Unmarshal(ob.Observation, observationProto); err != nil {
			dp.logger.Error("DecryptionReporting Report: cannot unmarshal observation, skipping it", commontypes.LogFields{
				"error":    err,
				"observer": ob.Observer,
			})
			continue
		}

		for _, decryptionShareWithID := range observationProto.DecryptionShares {
			ciphertextID := string(decryptionShareWithID.CiphertextId)
			ciphertext, ok := ciphertexts[ciphertextID]
			if !ok {
				dp.logger.Error("DecryptionReporting Report: there is not ciphertext in the query with matching id", commontypes.LogFields{
					"ciphertextID": ciphertextID,
					"observer":     ob.Observer,
				})
				continue
			}

			validDecryptionShare, err := dp.getValidDecryptionShare(ob.Observer,
				ciphertext, decryptionShareWithID.DecryptionShare)
			if err != nil {
				dp.logger.Error("DecryptionReporting Report: invalid decryption share", commontypes.LogFields{
					"error":        err,
					"ciphertextID": ciphertextID,
					"observer":     ob.Observer,
				})
				continue
			}

			validDecryptionShares[ciphertextID] = append(validDecryptionShares[ciphertextID], validDecryptionShare)
			if len(validDecryptionShares[ciphertextID]) >= fPlusOne {
				dp.logger.Trace("DecryptionReporting Report: we have already f+1 valid decryption shares", commontypes.LogFields{
					"ciphertextID": ciphertextID,
					"observer":     ob.Observer,
				})
				break
			}
		}
	}

	reportProto := Report{}
	for id, decrShares := range validDecryptionShares {
		ciphertext, ok := ciphertexts[id]
		if !ok {
			dp.logger.Error("DecryptionReporting Report: there is not ciphertext in the query with matching id, skipping aggregation of decryption shares", commontypes.LogFields{
				"ciphertextID": id,
			})
			continue
		}

		// OCR2.0 guaranties 2f+1 observations are from distinct oracles
		// which guaranties f+1 valid observations and, hence, f+1 valid decryption shares.
		// Therefore, here it is guaranteed that len(decrShares) > f.
		plaintext, err := tdh2easy.Aggregate(ciphertext, decrShares, dp.genericConfig.N)
		if err != nil {
			dp.logger.Error("DecryptionReporting Report: cannot aggregate decryption shares", commontypes.LogFields{
				"error":        err,
				"ciphertextID": id,
			})
			continue
		}

		dp.logger.Debug("DecryptionReporting Report: plaintext aggregated successfully", commontypes.LogFields{
			"epoch":        ts.Epoch,
			"round":        ts.Round,
			"ciphertextID": id,
		})
		reportProto.ProcessedDecryptedRequests = append(reportProto.ProcessedDecryptedRequests, &ProcessedDecryptionRequest{
			CiphertextId: []byte(id),
			Plaintext:    plaintext,
		})
	}

	dp.logger.Debug("DecryptionReporting Report: end", commontypes.LogFields{
		"epoch":                      ts.Epoch,
		"round":                      ts.Round,
		"aggregatedDecryptionShares": len(reportProto.ProcessedDecryptedRequests),
		"reporting":                  len(reportProto.ProcessedDecryptedRequests) > 0,
	})

	if len(reportProto.ProcessedDecryptedRequests) == 0 {
		return false, nil, nil
	}

	reportBytes, err := proto.Marshal(&reportProto)
	if err != nil {
		return false, nil, fmt.Errorf("cannot marshal report: %w", err)
	}
	return true, reportBytes, nil
}

func (dp *decryptionPlugin) getValidDecryptionShare(observer commontypes.OracleID,
	ciphertext *tdh2easy.Ciphertext, decryptionShareBytes []byte) (*tdh2easy.DecryptionShare, error) {
	decryptionShare := &tdh2easy.DecryptionShare{}
	if err := decryptionShare.Unmarshal(decryptionShareBytes); err != nil {
		return nil, fmt.Errorf("cannot unmarshal decryption share: %w", err)
	}

	expectedKeyShareIndex, ok := dp.oracleToKeyShare[observer]
	if !ok {
		return nil, fmt.Errorf("invalid observer ID")
	}

	if expectedKeyShareIndex != decryptionShare.Index() {
		return nil, fmt.Errorf("invalid decryption share index: expected %d and got %d", expectedKeyShareIndex, decryptionShare.Index())
	}

	if err := tdh2easy.VerifyShare(ciphertext, dp.publicKey, decryptionShare); err != nil {
		return nil, fmt.Errorf("decryption share verification failed: %w", err)
	}
	return decryptionShare, nil
}

// ShouldAcceptFinalizedReport updates the decryption queue.
// Returns always false as the report will not be transmitted on-chain.
func (dp *decryptionPlugin) ShouldAcceptFinalizedReport(ctx context.Context, ts types.ReportTimestamp, report types.Report) (bool, error) {
	dp.logger.Debug("DecryptionReporting ShouldAcceptFinalizedReport: start", commontypes.LogFields{
		"epoch": ts.Epoch,
		"round": ts.Round,
	})

	reportProto := &Report{}
	if err := proto.Unmarshal(report, reportProto); err != nil {
		return false, fmt.Errorf("cannot unmarshal report: %w", err)
	}

	for _, item := range reportProto.ProcessedDecryptedRequests {
		dp.decryptionQueue.SetResult(item.CiphertextId, item.Plaintext)
	}

	dp.logger.Debug("DecryptionReporting ShouldAcceptFinalizedReport: end", commontypes.LogFields{
		"epoch":     ts.Epoch,
		"round":     ts.Round,
		"accepting": false,
	})

	return false, nil
}

// ShouldTransmitAcceptedReport is a no-op
func (dp *decryptionPlugin) ShouldTransmitAcceptedReport(ctx context.Context, ts types.ReportTimestamp, report types.Report) (bool, error) {
	return false, nil
}

// Close complies with ReportingPlugin
func (dp *decryptionPlugin) Close() error {
	dp.logger.Debug("DecryptionReporting Close", nil)
	return nil
}

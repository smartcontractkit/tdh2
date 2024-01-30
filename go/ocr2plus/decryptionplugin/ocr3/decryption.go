package ocr3decryptionplugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2/types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin"
	"github.com/smartcontractkit/tdh2/go/ocr2/decryptionplugin/config"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"google.golang.org/protobuf/proto"
)

type DecryptionReportingPluginFactory struct {
	DecryptionQueue  decryptionplugin.DecryptionQueuingService
	ConfigParser     config.ConfigParser
	PublicKey        *tdh2easy.PublicKey
	PrivKeyShare     *tdh2easy.PrivateShare
	OracleToKeyShare map[commontypes.OracleID]int
	Logger           commontypes.Logger
}

type decryptionPlugin struct {
	logger           commontypes.Logger
	decryptionQueue  decryptionplugin.DecryptionQueuingService
	publicKey        *tdh2easy.PublicKey
	privKeyShare     *tdh2easy.PrivateShare
	oracleToKeyShare map[commontypes.OracleID]int
	genericConfig    *types.ReportingPluginConfig
	specificConfig   *config.ReportingPluginConfigWrapper
}

type ReportInfo struct{}

// NewReportingPlugin complies with ReportingPluginFactory.
func (f DecryptionReportingPluginFactory) NewReportingPlugin(rpConfig types.ReportingPluginConfig) (ocr3types.ReportingPlugin[ReportInfo], ocr3types.ReportingPluginInfo, error) {
	pluginConfig, err := f.ConfigParser.ParseConfig(rpConfig.OffchainConfig)
	if err != nil {
		return nil,
			ocr3types.ReportingPluginInfo{},
			fmt.Errorf("unable to decode reporting plugin config: %w", err)
	}

	// The number of decryption shares K needed to reconstruct the plaintext should satisfy F<K<=2F+1.
	// The lower bound ensure that no F parties can alone reconstruct the secret.
	// The upper bound ensures that there can be always enough decryption shares.
	// It depends on the minimum number of observations collected by the leader (2F+1).
	if int(pluginConfig.Config.K) <= rpConfig.F || int(pluginConfig.Config.K) > 2*rpConfig.F+1 {
		return nil,
			ocr3types.ReportingPluginInfo{},
			fmt.Errorf("invalid configuration with K=%d and F=%d: decryption threshold K must satisfy F < K <= 2F+1", pluginConfig.Config.K, rpConfig.F)
	}

	info := ocr3types.ReportingPluginInfo{
		Name: "ThresholdDecryption",
		Limits: ocr3types.ReportingPluginLimits{
			MaxQueryLength:       int(pluginConfig.Config.GetMaxQueryLengthBytes()),
			MaxObservationLength: int(pluginConfig.Config.GetMaxObservationLengthBytes()),
			MaxOutcomeLength:     int(pluginConfig.Config.GetMaxReportLengthBytes()),
			MaxReportLength:      int(pluginConfig.Config.GetMaxReportLengthBytes()),
			MaxReportCount:       int(pluginConfig.Config.GetRequestCountLimit()),
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
func (dp *decryptionPlugin) Query(ctx context.Context, outctx ocr3types.OutcomeContext) (types.Query, error) {
	dp.logger.Debug("DecryptionReporting Query: start", commontypes.LogFields{
		"seqNr": outctx.SeqNr,
	})

	decryptionRequests := dp.decryptionQueue.GetRequests(
		int(dp.specificConfig.Config.RequestCountLimit),
		int(dp.specificConfig.Config.RequestTotalBytesLimit),
	)

	queryProto := decryptionplugin.Query{}
	ciphertextIDs := make(map[string]bool)
	allIDs := []string{}
	for _, request := range decryptionRequests {
		if _, ok := ciphertextIDs[string(request.CiphertextId)]; ok {
			dp.logger.Error("DecryptionReporting Query: duplicate request, skipping it", commontypes.LogFields{
				"ciphertextID": request.CiphertextId.String(),
			})
			continue
		}
		ciphertextIDs[string(request.CiphertextId)] = true

		ciphertext := &tdh2easy.Ciphertext{}
		if err := ciphertext.UnmarshalVerify(request.Ciphertext, dp.publicKey); err != nil {
			dp.decryptionQueue.SetResult(request.CiphertextId, nil, decryptionplugin.ErrUnmarshalling)
			dp.logger.Error("DecryptionReporting Query: cannot unmarshal the ciphertext, skipping it", commontypes.LogFields{
				"error":        err,
				"ciphertextID": request.CiphertextId.String(),
			})
			continue
		}
		queryProto.DecryptionRequests = append(queryProto.GetDecryptionRequests(), &decryptionplugin.CiphertextWithID{
			CiphertextId: request.CiphertextId,
			Ciphertext:   request.Ciphertext,
		})
		allIDs = append(allIDs, request.CiphertextId.String())
	}

	dp.logger.Debug("DecryptionReporting Query: end", commontypes.LogFields{
		"seqNr":         outctx.SeqNr,
		"queryLen":      len(queryProto.DecryptionRequests),
		"ciphertextIDs": allIDs,
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
func (dp *decryptionPlugin) Observation(ctx context.Context, outctx ocr3types.OutcomeContext, query types.Query) (types.Observation, error) {
	dp.logger.Debug("DecryptionReporting Observation: start", commontypes.LogFields{
		"seqNr": outctx.SeqNr,
	})

	ciphertexts, err := dp.getCiphertexts(query)
	if err != nil {
		return nil, fmt.Errorf("cannot process the query: %w", err)
	}

	ciphertextIDs := make(map[string]bool)
	observationProto := decryptionplugin.Observation{}
	decryptedIDs := []string{}

	for ciphertextIdRawStr, ciphertext := range ciphertexts {
		if _, ok := ciphertextIDs[ciphertextIdRawStr]; ok {
			dp.logger.Error("DecryptionReporting Observation: duplicate request in the same query, the leader is faulty", commontypes.LogFields{
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			return nil, fmt.Errorf("duplicate request in the same query")
		}
		ciphertextIDs[ciphertextIdRawStr] = true

		if dp.specificConfig.Config.RequireLocalRequestCheck {
			queueCiphertextBytes, err := dp.decryptionQueue.GetCiphertext(ciphertext.ciphertextId)
			if err != nil && errors.Is(err, decryptionplugin.ErrNotFound) {
				dp.logger.Warn("DecryptionReporting Observation: cannot find ciphertext locally, skipping it", commontypes.LogFields{
					"error":        err,
					"ciphertextID": ciphertext.ciphertextId.String(),
				})
				continue
			} else if err != nil {
				dp.logger.Error("DecryptionReporting Observation: failed when looking for ciphertext locally, skipping it", commontypes.LogFields{
					"error":        err,
					"ciphertextID": ciphertext.ciphertextId.String(),
				})
				continue
			}
			if !bytes.Equal(queueCiphertextBytes, ciphertext.ciphertextBytes) {
				dp.logger.Error("DecryptionReporting Observation: local ciphertext does not match the query ciphertext, skipping it", commontypes.LogFields{
					"ciphertextID": ciphertext.ciphertextId.String(),
				})
				continue
			}
		}

		decryptionShare, err := tdh2easy.Decrypt(ciphertext.ciphertext, dp.privKeyShare)
		if err != nil {
			dp.decryptionQueue.SetResult(ciphertext.ciphertextId, nil, decryptionplugin.ErrDecryption)
			dp.logger.Error("DecryptionReporting Observation: cannot decrypt the ciphertext with the private key share", commontypes.LogFields{
				"error":        err,
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			continue
		}
		decryptionShareBytes, err := decryptionShare.Marshal()
		if err != nil {
			dp.logger.Error("DecryptionReporting Observation: cannot marshal the decryption share, skipping it", commontypes.LogFields{
				"error":        err,
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			continue
		}
		observationProto.DecryptionShares = append(observationProto.DecryptionShares, &decryptionplugin.DecryptionShareWithID{
			CiphertextId:    ciphertext.ciphertextId,
			DecryptionShare: decryptionShareBytes,
		})
		decryptedIDs = append(decryptedIDs, ciphertext.ciphertextId.String())
	}

	dp.logger.Debug("DecryptionReporting Observation: end", commontypes.LogFields{
		"seqNr":             outctx.SeqNr,
		"decryptedRequests": len(observationProto.DecryptionShares),
		"totalRequests":     len(ciphertexts),
		"ciphertextIDs":     decryptedIDs,
	})
	observationProtoBytes, err := proto.Marshal(&observationProto)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal observation: %w", err)
	}
	return observationProtoBytes, nil
}

func (dp *decryptionPlugin) ValidateObservation(outctx ocr3types.OutcomeContext, query types.Query, ao types.AttributedObservation) error {
	dp.logger.Debug("DecryptionReporting ValidateObservation: start", commontypes.LogFields{
		"seqNr": outctx.SeqNr,
	})

	observationProto := &decryptionplugin.Observation{}
	if err := proto.Unmarshal(ao.Observation, observationProto); err != nil {
		return fmt.Errorf("cannot unmarshal observation from observer %d: %w", ao.Observer, err)
	}

	ciphertexts, err := dp.getCiphertexts(query)
	if err != nil {
		return fmt.Errorf("cannot process query: %w", err)
	}

	ciphertextIDs := make(map[string]bool)
	for _, decryptionShareWithID := range observationProto.DecryptionShares {
		ciphertextId := decryptionplugin.CiphertextId(decryptionShareWithID.CiphertextId)
		ciphertextIdRawStr := string(ciphertextId)
		if _, ok := ciphertextIDs[ciphertextIdRawStr]; ok {
			return fmt.Errorf("the observation has multiple decryption shares for the same ciphertext id %s", ciphertextId.String())
		}
		ciphertextIDs[ciphertextIdRawStr] = true

		ciphertext, ok := ciphertexts[ciphertextIdRawStr]
		if !ok {
			fmt.Errorf("there is not ciphertext in the query with matching id %s", ciphertextId.String())
		}

		_, err := dp.getValidDecryptionShare(ao.Observer,
			ciphertext.ciphertext, decryptionShareWithID.DecryptionShare)
		if err != nil {
			return fmt.Errorf("invalid decryption share for ciphertext id %s: %w", ciphertextId.String(), err)
		}
	}

	dp.logger.Debug("DecryptionReporting ValidateObservation: end", commontypes.LogFields{
		"seqNr": outctx.SeqNr,
	})

	return nil
}

// ObservationQuorum returns the number of decryption shares K needed to reconstruct the plaintext should satisfy F<K<=2F+1.
// The lower bound ensure that no F parties can alone reconstruct the secret.
// The upper bound ensures that there can be always enough decryption shares.
// It depends on the minimum number of observations collected by the leader (2F+1).
func (dp *decryptionPlugin) ObservationQuorum(outctx ocr3types.OutcomeContext, query types.Query) (ocr3types.Quorum, error) {
	if int(dp.specificConfig.Config.K) <= dp.genericConfig.F || int(dp.specificConfig.Config.K) > dp.genericConfig.F+1 {
		return 0, fmt.Errorf("invalid configuration with K=%d and F=%d: decryption threshold K must satisfy F < K <= 2F+1", dp.specificConfig.Config.K, dp.genericConfig.F)
	}
	return ocr3types.Quorum(dp.specificConfig.Config.K + 1), nil
}

// Outcome aggregates decryption shares from Observations to derive the plaintext.
func (dp *decryptionPlugin) Outcome(outctx ocr3types.OutcomeContext, query types.Query, aos []types.AttributedObservation) (ocr3types.Outcome, error) {
	dp.logger.Debug("DecryptionReporting Outcome: start", commontypes.LogFields{
		"seqNr":         outctx.SeqNr,
		"nObservations": len(aos),
	})

	ciphertexts, err := dp.getCiphertexts(query)
	if err != nil {
		return nil, fmt.Errorf("cannot process query: %w", err)
	}

	validDecryptionShares := make(map[string][]*tdh2easy.DecryptionShare)
	for _, ob := range aos {
		observationProto := &decryptionplugin.Observation{}
		if err := proto.Unmarshal(ob.Observation, observationProto); err != nil {
			dp.logger.Error("DecryptionReporting Outcome: cannot unmarshal observation, skipping it", commontypes.LogFields{
				"error":    err,
				"observer": ob.Observer,
			})
			continue
		}

		ciphertextIDs := make(map[string]bool)
		for _, decryptionShareWithID := range observationProto.DecryptionShares {
			ciphertextId := decryptionplugin.CiphertextId(decryptionShareWithID.CiphertextId)
			ciphertextIdRawStr := string(ciphertextId)
			if _, ok := ciphertextIDs[ciphertextIdRawStr]; ok {
				dp.logger.Error("DecryptionReporting Outcome: the observation has multiple decryption shares for the same ciphertext id", commontypes.LogFields{
					"ciphertextID": ciphertextId.String(),
					"observer":     ob.Observer,
				})
				continue
			}
			ciphertextIDs[ciphertextIdRawStr] = true

			ciphertext, ok := ciphertexts[ciphertextIdRawStr]
			if !ok {
				dp.logger.Error("DecryptionReporting Outcome: there is not ciphertext in the query with matching id", commontypes.LogFields{
					"ciphertextID": ciphertextId.String(),
					"observer":     ob.Observer,
				})
				continue
			}

			validDecryptionShare, err := dp.getValidDecryptionShare(ob.Observer,
				ciphertext.ciphertext, decryptionShareWithID.DecryptionShare)
			if err != nil {
				dp.logger.Error("DecryptionReporting Outcome: invalid decryption share", commontypes.LogFields{
					"error":        err,
					"ciphertextID": ciphertextId.String(),
					"observer":     ob.Observer,
				})
				continue
			}

			if len(validDecryptionShares[ciphertextIdRawStr]) < int(dp.specificConfig.Config.K) {
				validDecryptionShares[ciphertextIdRawStr] = append(validDecryptionShares[ciphertextIdRawStr], validDecryptionShare)
			} else {
				dp.logger.Trace("DecryptionReporting Outcome: we have already k valid decryption shares", commontypes.LogFields{
					"ciphertextID": ciphertextId.String(),
					"observer":     ob.Observer,
				})
			}
		}
	}

	outcomeProto := decryptionplugin.Outcome{}
	for ciphertextIdRawStr, ciphertext := range ciphertexts {
		decrShares, ok := validDecryptionShares[ciphertextIdRawStr]
		if !ok {
			// Request not included in any observation in the current round.
			dp.logger.Debug("DecryptionReporting Outcome: ciphertextID was not included in any observation in the current round", commontypes.LogFields{
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			continue
		}
		ciphertext, ok := ciphertexts[ciphertextIdRawStr]
		if !ok {
			dp.logger.Error("DecryptionReporting Outcome: there is not ciphertext in the query with matching id, skipping aggregation of decryption shares", commontypes.LogFields{
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			continue
		}

		if len(decrShares) < int(dp.specificConfig.Config.K) {
			dp.logger.Debug("DecryptionReporting Outcome: not enough valid decryption shares after processing all observations, skipping aggregation of decryption shares", commontypes.LogFields{
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			continue
		}

		plaintext, err := tdh2easy.Aggregate(ciphertext.ciphertext, decrShares, dp.genericConfig.N)
		if err != nil {
			dp.decryptionQueue.SetResult(ciphertext.ciphertextId, nil, decryptionplugin.ErrAggregation)
			dp.logger.Error("DecryptionReporting Outcome: cannot aggregate decryption shares", commontypes.LogFields{
				"error":        err,
				"ciphertextID": ciphertext.ciphertextId.String(),
			})
			continue
		}

		dp.logger.Debug("DecryptionReporting Outcome: plaintext aggregated successfully", commontypes.LogFields{
			"seqNr":        outctx.SeqNr,
			"ciphertextID": ciphertext.ciphertextId.String(),
		})
		outcomeProto.ProcessedDecryptedRequests = append(outcomeProto.ProcessedDecryptedRequests, &decryptionplugin.ProcessedDecryptionRequest{
			CiphertextId: ciphertext.ciphertextId,
			Plaintext:    plaintext,
		})
	}

	dp.logger.Debug("DecryptionReporting Outcome: end", commontypes.LogFields{
		"seqNr":                      outctx.SeqNr,
		"aggregatedDecryptionShares": len(outcomeProto.ProcessedDecryptedRequests),
		"reporting":                  len(outcomeProto.ProcessedDecryptedRequests) > 0,
	})

	outcomeBytes, err := proto.Marshal(&outcomeProto)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal report: %w", err)
	}
	return outcomeBytes, nil
}

func (dp *decryptionPlugin) Reports(seqNr uint64, rawOutcome ocr3types.Outcome) ([]ocr3types.ReportWithInfo[ReportInfo], error) {
	dp.logger.Debug("DecryptionReporting Reports: start", commontypes.LogFields{
		"seqNr": seqNr,
	})

	var outcome decryptionplugin.Outcome
	if err := proto.Unmarshal(rawOutcome, &outcome); err != nil {
		return nil, fmt.Errorf("error unmarshalling outcome: %w", err)
	}

	rwis := []ocr3types.ReportWithInfo[ReportInfo]{}
	for _, processedDecryptiondRequest := range outcome.ProcessedDecryptedRequests {
		reportBytes, err := proto.Marshal(processedDecryptiondRequest)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal report: %w", err)
		}
		rwis = append(rwis,
			ocr3types.ReportWithInfo[ReportInfo]{
				reportBytes,
				ReportInfo{},
			})
	}

	dp.logger.Debug("DecryptionReporting Reports: end", commontypes.LogFields{
		"seqNr":    seqNr,
		"nReports": len(rwis),
	})

	return rwis, nil
}

// ShouldAcceptAttestedReport updates the decryption queue.
// Returns always false as the report will not be transmitted on-chain.
func (dp *decryptionPlugin) ShouldAcceptAttestedReport(ctx context.Context, seqNr uint64, rwi ocr3types.ReportWithInfo[ReportInfo]) (bool, error) {
	dp.logger.Debug("DecryptionReporting ShouldAcceptFinalizedReport: start", commontypes.LogFields{
		"SeqNr": seqNr,
	})

	reportProto := &decryptionplugin.Report{}
	if err := proto.Unmarshal(rwi.Report, reportProto); err != nil {
		return false, fmt.Errorf("cannot unmarshal report: %w", err)
	}

	for _, item := range reportProto.ProcessedDecryptedRequests {
		dp.decryptionQueue.SetResult(item.CiphertextId, item.Plaintext, nil)
	}

	dp.logger.Debug("DecryptionReporting ShouldAcceptFinalizedReport: end", commontypes.LogFields{
		"SeqNr":     seqNr,
		"accepting": false,
	})

	return false, nil
}

// ShouldTransmitAcceptedReport is a no-op
func (dp *decryptionPlugin) ShouldTransmitAcceptedReport(ctx context.Context, seqNr uint64, r ocr3types.ReportWithInfo[ReportInfo]) (bool, error) {
	return false, nil
}

type ciphertextStruct struct {
	ciphertextId    decryptionplugin.CiphertextId
	ciphertextBytes []byte
	ciphertext      *tdh2easy.Ciphertext
}

func (dp *decryptionPlugin) getCiphertexts(query types.Query) (map[string]ciphertextStruct, error) {
	ciphertexts := make(map[string]ciphertextStruct)
	queryProto := &decryptionplugin.Query{}
	if err := proto.Unmarshal(query, queryProto); err != nil {
		return nil, fmt.Errorf("cannot unmarshal query: %w ", err)
	}
	for _, request := range queryProto.DecryptionRequests {
		ciphertextId := decryptionplugin.CiphertextId(request.CiphertextId)
		ciphertext := &tdh2easy.Ciphertext{}
		if err := ciphertext.UnmarshalVerify(request.Ciphertext, dp.publicKey); err != nil {
			dp.logger.Error("DecryptionReporting: cannot unmarshall and verify the ciphertexts, the leader is faulty", commontypes.LogFields{
				"error":        err,
				"ciphertextID": string(ciphertextId),
			})
			return nil, fmt.Errorf("cannot unmarshal and verify the ciphertext: %w", err)
		}
		ciphertexts[string(ciphertextId)] = ciphertextStruct{
			ciphertextId,
			request.Ciphertext,
			ciphertext,
		}
	}
	return ciphertexts, nil
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

// Close complies with ReportingPlugin
func (dp *decryptionPlugin) Close() error {
	dp.logger.Debug("DecryptionReporting Close", nil)
	return nil
}

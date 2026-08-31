package ackhandler

import (
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter"
)

// A CongestionControllerFactory builds the congestion controller for a
// connection. It is called once when the connection is created, and again after
// each path migration, since the previous path's model no longer applies.
type CongestionControllerFactory func(
	rttStats congestion.RTTStatsProvider,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) congestion.SendAlgorithmWithDebugInfos

// defaultCongestionController is BBRv3, used whenever the application does not
// supply one of its own.
func defaultCongestionController(
	rttStats congestion.RTTStatsProvider,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) congestion.SendAlgorithmWithDebugInfos {
	return congestion.NewBBRSender(congestion.DefaultClock{}, rttStats, initialMaxDatagramSize, qlogger)
}

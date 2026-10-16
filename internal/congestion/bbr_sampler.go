package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// This file implements the delivery rate sampling algorithm of
// draft-ietf-ccwg-bbr-06 §4.1. BBR does not derive bandwidth from cwnd/RTT the
// way Reno's pacer does; it measures the rate at which data is actually
// delivered, by snapshotting connection-level delivery counters when a packet
// is sent and differencing them when that packet is acknowledged.

// bbrPacketState is the per-packet state snapshotted at transmit time
// (§4.1.2.2 "Per-packet state").
type bbrPacketState struct {
	sendTime      monotime.Time
	firstSendTime monotime.Time      // C.first_send_time at transmit
	deliveredTime monotime.Time      // C.delivered_time at transmit
	delivered     protocol.ByteCount // C.delivered at transmit
	lost          protocol.ByteCount // C.lost at transmit
	txInFlight    protocol.ByteCount // C.inflight at transmit, including this packet
	size          protocol.ByteCount
	isAppLimited  bool
}

// bbrRateSample is the per-ACK rate sample RS (§2.3).
type bbrRateSample struct {
	// deliveryRate is valid only if hasRate is set. An interval shorter than
	// min_rtt yields no reliable rate (§4.1.2.3), which is what makes it safe
	// for us to run this per acknowledged packet rather than per ACK frame.
	deliveryRate Bandwidth
	hasRate      bool

	delivered      protocol.ByteCount // RS.delivered
	priorDelivered protocol.ByteCount // RS.prior_delivered
	newlyAcked     protocol.ByteCount // RS.newly_acked
	txInFlight     protocol.ByteCount // RS.tx_in_flight
	lost           protocol.ByteCount // RS.lost
	interval       time.Duration
	isAppLimited   bool
}

// maxTrackedPackets bounds the sampler's per-packet map. Every ack-eliciting
// packet quic-go sends is eventually either acknowledged or declared lost, and
// both paths delete the entry — except Path MTU probes, which are excluded from
// OnCongestionEvent, and packets in a packet number space that gets dropped.
// Both are O(10) per connection, but the cap keeps a pathological path from
// growing the map without bound on a long-lived connection.
const maxTrackedPackets = 2 * protocol.MaxOutstandingSentPackets

// bbrSampler tracks connection-level delivery state (§4.1.2.1) and produces a
// rate sample per acknowledged packet.
type bbrSampler struct {
	delivered     protocol.ByteCount // C.delivered
	lost          protocol.ByteCount // C.lost
	deliveredTime monotime.Time      // C.delivered_time
	firstSendTime monotime.Time      // C.first_send_time

	// appLimited is C.app_limited: the value C.delivered must exceed before the
	// application-limited phase is considered over. Zero means not app-limited.
	appLimited protocol.ByteCount

	packets map[protocol.PacketNumber]bbrPacketState
}

func newBBRSampler() *bbrSampler {
	return &bbrSampler{packets: make(map[protocol.PacketNumber]bbrPacketState)}
}

// OnPacketSent snapshots the delivery state for a packet (§4.1.2.2).
//
// bytesInFlight is quic-go's value *after* adding this packet, which is what
// the spec's P.tx_in_flight wants ("includes data in P").
//
// Note that quic-go drives a single congestion controller from all three packet
// number spaces, which number their packets independently, so two in-flight
// packets can share a packet number during the handshake. A colliding send
// overwrites the older entry; the older packet then produces no sample when it
// is acked. This costs a handful of samples in the first round trips of a
// connection, while BBR is still in Startup with no bandwidth estimate anyway.
func (s *bbrSampler) OnPacketSent(
	sendTime monotime.Time,
	pn protocol.PacketNumber,
	size protocol.ByteCount,
	bytesInFlight protocol.ByteCount,
	isAckEliciting bool,
) {
	if !isAckEliciting {
		// Not tracked by quic-go's bytesInFlight, and never acknowledged on its
		// own, so it can produce no delivery rate sample.
		return
	}
	// No data in flight: any ACK arriving after now measures an interval the
	// network was able to drain completely, so restart the sampling interval
	// here rather than at the last ACK (§4.1.2.2).
	if bytesInFlight == size {
		s.firstSendTime = sendTime
		s.deliveredTime = sendTime
	}
	if len(s.packets) >= maxTrackedPackets {
		s.evictOldest()
	}
	s.packets[pn] = bbrPacketState{
		sendTime:      sendTime,
		firstSendTime: s.firstSendTime,
		deliveredTime: s.deliveredTime,
		delivered:     s.delivered,
		lost:          s.lost,
		txInFlight:    bytesInFlight,
		size:          size,
		isAppLimited:  s.appLimited != 0,
	}
}

// OnPacketAcked folds a newly acknowledged packet into the delivery counters and
// returns the resulting rate sample (§4.1.2.3).
//
// The spec generates one sample per ACK frame, using the newest packet that ACK
// covers. quic-go reports acknowledged packets one at a time with no end-of-ACK
// callback, so we generate a sample per packet instead. The samples for the
// older packets of a stretched ACK span shorter intervals; the min_rtt floor
// below discards them, leaving the newest packet's sample — the one the spec
// asks for — as the only one that reaches the bandwidth filter.
func (s *bbrSampler) OnPacketAcked(
	ackTime monotime.Time,
	pn protocol.PacketNumber,
	minRTT time.Duration,
) (bbrRateSample, bool) {
	p, ok := s.packets[pn]
	if !ok {
		return bbrRateSample{}, false
	}
	delete(s.packets, pn)

	s.delivered += p.size
	s.deliveredTime = ackTime

	rs := bbrRateSample{
		newlyAcked:     p.size,
		delivered:      s.delivered - p.delivered,
		priorDelivered: p.delivered,
		txInFlight:     p.txInFlight,
		lost:           s.lost - p.lost,
		isAppLimited:   p.isAppLimited,
	}

	// The application-limited phase ends once everything that was in flight when
	// it began has been delivered (§4.1.2.3 GenerateRateSample).
	if s.appLimited != 0 && s.delivered > s.appLimited {
		s.appLimited = 0
	}

	// Start the next sampling interval at this packet's send time.
	s.firstSendTime = p.sendTime

	sendElapsed := p.sendTime.Sub(p.firstSendTime)
	ackElapsed := ackTime.Sub(p.deliveredTime)
	// Use the longer of the two: the rate is bounded both by how fast we sent
	// and by how fast the acks came back.
	interval := max(sendElapsed, ackElapsed)
	rs.interval = interval

	// An interval shorter than min_rtt cannot describe a full delivery cycle, so
	// the rate it implies is not reliable.
	if interval <= 0 || (minRTT > 0 && interval < minRTT) {
		return rs, true
	}
	rs.deliveryRate = BandwidthFromDelta(rs.delivered, interval)
	rs.hasRate = rs.deliveryRate > 0
	return rs, true
}

// OnPacketLost accounts for a declared-lost packet and returns the state it was
// sent with, which BBR needs to judge whether inflight was too high (§5.5.10.2).
func (s *bbrSampler) OnPacketLost(pn protocol.PacketNumber, lostBytes protocol.ByteCount) (bbrPacketState, bool) {
	p, ok := s.packets[pn]
	if !ok {
		// Still count the loss: C.lost feeds RS.lost for packets that are
		// tracked, and undercounting it would make loss look milder than it was.
		s.lost += lostBytes
		return bbrPacketState{}, false
	}
	delete(s.packets, pn)
	s.lost += p.size
	return p, true
}

// MarkAppLimited records that the connection ran out of data to send
// (§4.1.2.4). Samples taken until everything currently in flight is delivered
// measure the application's rate, not the path's, and must not lower max_bw.
func (s *bbrSampler) MarkAppLimited(bytesInFlight protocol.ByteCount) {
	s.appLimited = max(s.delivered+bytesInFlight, 1)
}

func (s *bbrSampler) isAppLimited() bool { return s.appLimited != 0 }

// evictOldest drops the entry with the lowest packet number. Called only when
// the map hits maxTrackedPackets, which requires packets that are never acked
// and never reported lost, so this is a leak backstop rather than a hot path.
func (s *bbrSampler) evictOldest() {
	oldest := protocol.InvalidPacketNumber
	for pn := range s.packets {
		if oldest == protocol.InvalidPacketNumber || pn < oldest {
			oldest = pn
		}
	}
	if oldest != protocol.InvalidPacketNumber {
		delete(s.packets, oldest)
	}
}

package congestion

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

// simBase keeps the mock clock away from zero, so that monotime's IsZero() means
// "unset" in the sender rather than "the start of the test".
const simBase = time.Hour

func newTestBBRSender(t *testing.T) (*bbrSender, *mockClock, *utils.RTTStats) {
	t.Helper()
	clock := mockClock(monotime.Time(0).Add(simBase))
	rttStats := utils.NewRTTStats()
	s := newBBRSender(
		&clock,
		rttStats,
		&utils.ConnectionStats{},
		maxDatagramSize,
		bbrInitialCwndPackets*maxDatagramSize,
		protocol.MaxCongestionWindowPackets*maxDatagramSize,
		nil,
	)
	return s, &clock, rttStats
}

func TestBBRStartsInStartup(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	require.Equal(t, bbrStartup, s.mode)
	require.True(t, s.InSlowStart())
	require.False(t, s.InRecovery())
	require.InDelta(t, bbrStartupPacingGain, s.pacingGain, 1e-9)
	require.InDelta(t, bbrDefaultCwndGain, s.cwndGain, 1e-9)
	require.Equal(t, bbrInitialCwndPackets*maxDatagramSize, s.GetCongestionWindow())
	require.Positive(t, s.pacingRate, "InitPacingRate must seed a non-zero rate")
}

// TestBBRPacerUsesPacingRate is the regression test for the failure mode that
// makes a BBR implementation silently behave like a fixed-rate one: the pacer
// must be driven by BBR.pacing_rate, which already carries pacing_gain and the
// 1% margin, and not by the raw bandwidth estimate.
func TestBBRPacerUsesPacingRate(t *testing.T) {
	s, clock, _ := newTestBBRSender(t)
	const bw = 10 * 1000 * 1000 * BitsPerSecond

	s.maxBWFilter.Update(int64(bw), 0, bbrMaxBwFilterLen)
	require.Equal(t, bw, s.bw())

	for _, tc := range []struct {
		name string
		gain float64
	}{
		{"startup", bbrStartupPacingGain},
		{"drain", bbrDrainPacingGain},
		{"probe_bw_down", bbrProbeBWDownGain},
		{"probe_bw_up", bbrProbeBWUpGain},
		{"cruise", 1.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.fullBWReached = true // allow the rate to move in both directions
			s.pacingGain = tc.gain
			s.setPacingRate()

			want := Bandwidth(tc.gain * float64(bw) * (100 - bbrPacingMarginPercent) / 100)
			require.Equal(t, want, s.pacingRate)

			// The pacer must hand out budget at that rate, not at bw and not at
			// the 5/4 headroom rate newPacer applies for Reno. Keep the interval
			// short enough that the accumulated budget stays below the pacer's
			// burst cap, which would otherwise flatten every rate to the same
			// value and hide the difference.
			s.pacer.budgetAtLastSent = 0
			s.pacer.lastSentTime = clock.Now()
			const elapsed = 2 * time.Millisecond
			clock.Advance(elapsed)
			budget := s.pacer.Budget(clock.Now())
			expected := bandwidthToBytes(want, elapsed)
			require.Less(t, expected, s.pacer.maxBurstSize(), "test setup: interval must stay under the burst cap")
			require.InEpsilon(t, float64(expected), float64(budget), 0.02)
		})
	}
}

func TestBBRDrainUsesSpecPacingGain(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.enterDrain()
	require.Equal(t, bbrDrain, s.mode)
	// draft-ietf-ccwg-bbr-06 §5.3.2 specifies 0.5, not the 1/2.77 of earlier
	// BBR versions. A gain above 1 would mean Drain never drains.
	require.InDelta(t, 0.5, s.pacingGain, 1e-9)
	require.Less(t, s.pacingGain, 1.0)
}

func TestBBRExitsStartupOnBandwidthPlateau(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	const bw = 10 * 1000 * 1000 * BitsPerSecond

	// Three consecutive round starts without a 25% increase in delivery rate.
	for range bbrFullBWCount + 1 {
		s.roundStart = true
		s.checkFullBWReached(bbrRateSample{deliveryRate: bw})
	}
	require.True(t, s.fullBWReached)
	s.checkStartupDone()
	require.Equal(t, bbrDrain, s.mode)
}

func TestBBRStaysInStartupWhileBandwidthGrows(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	bw := Bandwidth(1000 * 1000)
	for range 10 {
		s.roundStart = true
		s.checkFullBWReached(bbrRateSample{deliveryRate: bw})
		bw = Bandwidth(float64(bw) * 1.5) // growing faster than the 25% threshold
	}
	require.False(t, s.fullBWReached)
	s.checkStartupDone()
	require.Equal(t, bbrStartup, s.mode)
}

func TestBBRIgnoresAppLimitedSamplesForStartupExit(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	// A flat delivery rate that is app-limited says nothing about the path, so
	// it must not count toward the plateau (draft §5.3.1.2).
	for range 10 {
		s.roundStart = true
		s.checkFullBWReached(bbrRateSample{deliveryRate: bw, isAppLimited: true})
	}
	require.False(t, s.fullBWReached)
	require.Equal(t, bbrStartup, s.mode)
}

func TestBBRAppLimitedSampleCannotLowerMaxBW(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	const high = 10 * 1000 * 1000 * BitsPerSecond
	const low = 1 * 1000 * 1000 * BitsPerSecond

	s.updateMaxBW(bbrRateSample{deliveryRate: high, hasRate: true, priorDelivered: 0})
	require.Equal(t, high, s.maxBW())

	// An app-limited sample below the current estimate is discarded: it measures
	// the application, not the path (draft §5.5.4).
	s.updateMaxBW(bbrRateSample{deliveryRate: low, hasRate: true, isAppLimited: true})
	require.Equal(t, high, s.maxBW())

	// A non-app-limited sample is admitted to the filter.
	s.updateMaxBW(bbrRateSample{deliveryRate: low, hasRate: true})
	require.Equal(t, high, s.maxBW(), "still the windowed max")
}

func TestBBRExitsStartupOnHighLoss(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.inLossRecovery = true
	s.recoveryStartRound = 0
	s.roundCount = 1 // a full round has elapsed in recovery
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(10*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)

	inflight := 100 * maxDatagramSize
	// A loss rate well above the 2% threshold, spread over enough distinct
	// packets to satisfy the bbrStartupFullLoss criterion (draft §5.3.1.3).
	rs := bbrRateSample{txInFlight: inflight, lost: 10 * maxDatagramSize}
	s.checkStartupHighLoss(bbrStartupFullLoss, rs)
	require.True(t, s.fullBWReached)
	s.checkStartupDone()
	require.Equal(t, bbrDrain, s.mode)
}

func TestBBRDoesNotExitStartupOnLightLoss(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.inLossRecovery = true
	s.roundCount = 1
	inflight := 100 * maxDatagramSize

	// Below the 6-event threshold.
	s.checkStartupHighLoss(bbrStartupFullLoss-1, bbrRateSample{txInFlight: inflight, lost: 10 * maxDatagramSize})
	require.False(t, s.fullBWReached)

	// Enough events, but under the 2% loss rate.
	s.checkStartupHighLoss(bbrStartupFullLoss, bbrRateSample{txInFlight: inflight, lost: maxDatagramSize})
	require.False(t, s.fullBWReached)
}

func TestBBRStartupHighLossNeedsAFullRoundInRecovery(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.inLossRecovery = true
	s.recoveryStartRound = 5
	s.roundCount = 5 // recovery started this round; not a full round yet
	rs := bbrRateSample{txInFlight: 100 * maxDatagramSize, lost: 10 * maxDatagramSize}

	s.checkStartupHighLoss(bbrStartupFullLoss, rs)
	require.False(t, s.fullBWReached, "burst loss within a single round must not exit Startup")

	s.roundCount = 6
	s.checkStartupHighLoss(bbrStartupFullLoss, rs)
	require.True(t, s.fullBWReached)
}

func TestBBRStartupLossEventsResetEachRound(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.startupLossEvents = 4
	// A new packet-timed round trip starts a fresh count: §5.3.1.3 counts loss
	// ranges within one round, not across the whole recovery episode.
	s.updateRound(bbrRateSample{priorDelivered: 0})
	require.True(t, s.roundStart)
	require.Zero(t, s.startupLossEvents)
}

func TestBBRProbeBWCycleOrder(t *testing.T) {
	s, clock, _ := newTestBBRSender(t)
	s.fullBWReached = true
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(10*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)

	s.enterProbeBW()
	require.Equal(t, bbrProbeBWDown, s.mode)
	require.InDelta(t, bbrProbeBWDownGain, s.pacingGain, 1e-9)

	// Once inflight is under the BDP and leaves headroom, DOWN yields to CRUISE.
	s.inflightLongterm = bbrInfiniteInflight
	require.True(t, s.isTimeToCruise(0))
	s.startProbeBWCruise()
	require.Equal(t, bbrProbeBWCruise, s.mode)
	require.InDelta(t, 1.0, s.pacingGain, 1e-9)

	// The probe timer expiring moves CRUISE to REFILL.
	clock.Advance(s.bwProbeWait + time.Second)
	require.True(t, s.isTimeToProbeBW(bbrRateSample{}, clock.Now()))
	require.Equal(t, bbrProbeBWRefill, s.mode)
	require.InDelta(t, 1.0, s.pacingGain, 1e-9)

	// One full round of REFILL then starts UP.
	s.roundStart = true
	s.updateProbeBWCyclePhase(bbrRateSample{}, 0, clock.Now())
	require.Equal(t, bbrProbeBWUp, s.mode)
	require.InDelta(t, bbrProbeBWUpGain, s.pacingGain, 1e-9)
}

func TestBBRProbeBWUpReturnsToDownWhenPipeIsFull(t *testing.T) {
	s, clock, _ := newTestBBRSender(t)
	s.fullBWReached = true
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(10*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)
	s.enterProbeBW()
	s.startProbeBWUp(bbrRateSample{})
	require.Equal(t, bbrProbeBWUp, s.mode)

	s.fullBWNow = true // the plateau estimator says we have filled the pipe
	s.updateProbeBWCyclePhase(bbrRateSample{}, 0, clock.Now())
	require.Equal(t, bbrProbeBWDown, s.mode)
}

func TestBBRInflightTooHighCutsInflightLongterm(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.fullBWReached = true
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(10*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)
	s.enterProbeBW()
	s.startProbeBWUp(bbrRateSample{})
	s.cwnd = 100 * maxDatagramSize

	txInFlight := 100 * maxDatagramSize
	rs := bbrRateSample{txInFlight: txInFlight, lost: 5 * maxDatagramSize}
	require.True(t, s.isInflightTooHigh(rs))

	before := s.targetInflight()
	s.handleInflightTooHigh(rs)
	require.True(t, s.prevProbeTooHigh)
	require.Equal(t, bbrProbeBWDown, s.mode, "excess loss in UP must go back to DOWN")
	// The Beta floor keeps the reduction no sharper than CUBIC's 0.7x.
	require.GreaterOrEqual(t, s.inflightLongterm, protocol.ByteCount(float64(before)*bbrBeta))
}

func TestBBRLossBelowThresholdIsNotTooHigh(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	// 1% loss is under the 2% threshold, so the model must not react.
	rs := bbrRateSample{txInFlight: 100 * maxDatagramSize, lost: maxDatagramSize}
	require.False(t, s.isInflightTooHigh(rs))
}

func TestBBREntersAndExitsProbeRTT(t *testing.T) {
	s, clock, _ := newTestBBRSender(t)
	s.fullBWReached = true
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(10*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)
	s.enterProbeBW()
	s.cwnd = 100 * maxDatagramSize
	s.priorCwnd = s.cwnd

	// Nothing refreshes probe_rtt_min_delay for longer than ProbeRTTInterval.
	clock.Advance(bbrProbeRTTInterval + time.Second)
	s.updateMinRTT(clock.Now())
	require.True(t, s.probeRTTExpired)

	s.checkProbeRTT(bbrRateSample{}, 0, clock.Now())
	require.Equal(t, bbrProbeRTT, s.mode)
	require.InDelta(t, bbrProbeRTTCwndGain, s.cwndGain, 1e-9)

	// ProbeRTT holds for at least ProbeRTTDuration and one round.
	require.False(t, s.probeRTTDoneTime.IsZero(), "inflight was already below the ProbeRTT window")
	clock.Advance(bbrProbeRTTDuration + time.Millisecond)
	s.roundStart = true
	s.handleProbeRTT(0, clock.Now())
	require.NotEqual(t, bbrProbeRTT, s.mode, "ProbeRTT must end once the timer and a round have elapsed")
	require.True(t, s.mode.isProbeBW())
	require.Equal(t, 100*maxDatagramSize, s.cwnd, "cwnd is restored on exit")
}

func TestBBRProbeRTTBoundsCwnd(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(10*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)
	s.enterProbeRTT()
	s.cwnd = 1000 * maxDatagramSize
	s.boundCwndForProbeRTT()
	require.Equal(t, s.probeRTTCwnd(), s.cwnd)
	require.Less(t, s.cwnd, 1000*maxDatagramSize)
	require.GreaterOrEqual(t, s.cwnd, s.minCwnd())
}

func TestBBRCwndNeverBelowMinPipeCwnd(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.minRTT = time.Millisecond
	s.maxBWFilter.Update(1, 0, bbrMaxBwFilterLen) // a pathologically low estimate
	s.fullBWReached = true
	s.cwnd = 0
	s.setCwnd(bbrRateSample{newlyAcked: 0})
	require.GreaterOrEqual(t, s.cwnd, bbrMinPipeCwndPackets*maxDatagramSize)
}

func TestBBRCwndBoundedByMaxCongestionWindow(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.minRTT = time.Second
	s.maxBWFilter.Update(int64(100*1000*1000*1000*BitsPerSecond), 0, bbrMaxBwFilterLen)
	s.fullBWReached = true
	s.cwnd = protocol.MaxCongestionWindowPackets * maxDatagramSize
	s.setCwnd(bbrRateSample{newlyAcked: maxDatagramSize})
	require.LessOrEqual(t, s.cwnd, protocol.MaxCongestionWindowPackets*maxDatagramSize)
}

func TestBBRRTOReducesCwnd(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	s.cwnd = 100 * maxDatagramSize
	s.OnRetransmissionTimeout(true)
	require.Equal(t, maxDatagramSize, s.cwnd)
	require.Equal(t, 100*maxDatagramSize, s.priorCwnd, "the pre-RTO window is remembered")
}

func TestBBRRestartFromIdlePacesAtBandwidth(t *testing.T) {
	s, clock, _ := newTestBBRSender(t)
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	s.fullBWReached = true
	s.minRTT = 50 * time.Millisecond
	s.maxBWFilter.Update(int64(bw), 0, bbrMaxBwFilterLen)
	s.enterProbeBW()
	s.pacingRate = 1 // stale, far below the estimate

	// A send with nothing in flight restarts an idle connection: draft §5.4.1
	// says to pace at exactly bw so the flow returns to rate balance at once.
	s.OnPacketSent(clock.Now(), maxDatagramSize, 1, maxDatagramSize, true)
	require.Equal(t, Bandwidth(1.0*float64(bw)*(100-bbrPacingMarginPercent)/100), s.pacingRate)
	require.True(t, s.sampler.isAppLimited(), "an idle restart marks the flow app-limited")
}

func TestBBRSetMaxDatagramSizePanicsOnDecrease(t *testing.T) {
	s, _, _ := newTestBBRSender(t)
	require.Panics(t, func() { s.SetMaxDatagramSize(maxDatagramSize - 1) })
}

// ---- path simulation ----

// bbrTestPath is a single bottleneck link: a constant service rate, a fixed
// two-way propagation delay, and a finite buffer that drops on overflow.
type bbrTestPath struct {
	bw          Bandwidth
	minRTT      time.Duration
	bufferBytes protocol.ByteCount
	randomLoss  float64 // loss unrelated to congestion, e.g. a wireless hop
}

type bbrSimPacket struct {
	pn       protocol.PacketNumber
	size     protocol.ByteCount
	sendTime monotime.Time
	eventAt  monotime.Time // ack arrival, or loss declaration
	lost     bool
}

type bbrSim struct {
	clock    *mockClock
	rttStats *utils.RTTStats
	sender   *bbrSender
	path     bbrTestPath
	rng      *rand.Rand

	inflight   protocol.ByteCount
	nextPN     protocol.PacketNumber
	linkFreeAt monotime.Time
	pending    []bbrSimPacket

	delivered protocol.ByteCount
	lost      int
	maxRTT    time.Duration

	// alt drives an alternative controller (used by the Reno baseline in the
	// sweep); when nil, sender is used.
	alt SendAlgorithmWithDebugInfos
}

// cc returns the controller under test.
func (sim *bbrSim) cc() SendAlgorithmWithDebugInfos {
	if sim.alt != nil {
		return sim.alt
	}
	return sim.sender
}

func newBBRSim(t *testing.T, path bbrTestPath) *bbrSim {
	t.Helper()
	s, clock, rttStats := newTestBBRSender(t)
	return &bbrSim{
		clock:      clock,
		rttStats:   rttStats,
		sender:     s,
		path:       path,
		rng:        rand.New(rand.NewPCG(1, 2)),
		linkFreeAt: clock.Now(),
	}
}

func (sim *bbrSim) now() monotime.Time { return sim.clock.Now() }

func (sim *bbrSim) send() {
	const size = maxDatagramSize
	pn := sim.nextPN
	sim.nextPN++
	sim.inflight += size
	sim.cc().OnPacketSent(sim.now(), sim.inflight, pn, size, true)

	// Queueing: the link serves packets back to back, so a packet arriving while
	// the link is busy waits for the backlog to clear.
	serviceStart := max(sim.now(), sim.linkFreeAt)
	queued := bandwidthToBytes(sim.path.bw, serviceStart.Sub(sim.now()))
	serviceTime := time.Duration(float64(size) * 8 * float64(time.Second) / float64(sim.path.bw))
	sim.linkFreeAt = serviceStart.Add(serviceTime)

	lost := queued > sim.path.bufferBytes
	if sim.path.randomLoss > 0 && sim.rng.Float64() < sim.path.randomLoss {
		lost = true
	}
	if lost {
		// The link drops it; the sender only finds out via loss detection, which
		// RFC 9002 delays past the ack that would have carried it.
		sim.linkFreeAt = serviceStart // a dropped packet does not occupy the link
		sim.pending = append(sim.pending, bbrSimPacket{
			pn: pn, size: size, sendTime: sim.now(),
			eventAt: sim.now().Add(sim.path.minRTT + sim.path.minRTT/8), lost: true,
		})
		return
	}
	sim.pending = append(sim.pending, bbrSimPacket{
		pn: pn, size: size, sendTime: sim.now(),
		eventAt: sim.linkFreeAt.Add(sim.path.minRTT),
	})
}

// deliver hands the sender every event that is due at the current time.
func (sim *bbrSim) deliver() {
	remaining := sim.pending[:0]
	for _, p := range sim.pending {
		if p.eventAt.After(sim.now()) {
			remaining = append(remaining, p)
			continue
		}
		priorInFlight := sim.inflight
		sim.inflight -= p.size
		if p.lost {
			sim.lost++
			sim.cc().OnCongestionEvent(p.pn, p.size, priorInFlight)
			continue
		}
		rtt := p.eventAt.Sub(p.sendTime)
		sim.maxRTT = max(sim.maxRTT, rtt)
		sim.rttStats.UpdateRTT(rtt, 0)
		sim.delivered += p.size
		sim.cc().OnPacketAcked(p.pn, p.size, priorInFlight, sim.now())
	}
	sim.pending = remaining
}

// nextEvent returns the time of the earliest pending ack or loss declaration.
func (sim *bbrSim) nextEvent() (monotime.Time, bool) {
	var earliest monotime.Time
	found := false
	for _, p := range sim.pending {
		if !found || p.eventAt.Before(earliest) {
			earliest = p.eventAt
			found = true
		}
	}
	return earliest, found
}

// run drives the simulation for d of simulated time with an application that
// always has data to send.
func (sim *bbrSim) run(d time.Duration) {
	deadline := sim.now().Add(d)
	for sim.now().Before(deadline) {
		sent := false
		for sim.cc().CanSend(sim.inflight) && sim.cc().HasPacingBudget(sim.now()) {
			sim.send()
			sent = true
		}
		// Advance to whichever comes first: the next ack, or the moment the
		// pacer will release the next packet.
		next := deadline
		if ev, ok := sim.nextEvent(); ok && ev.Before(next) {
			next = ev
		}
		if sim.cc().CanSend(sim.inflight) {
			if until := sim.cc().TimeUntilSend(sim.inflight); !until.IsZero() && until.After(sim.now()) && until.Before(next) {
				next = until
			}
		}
		if !next.After(sim.now()) {
			if !sent {
				next = sim.now().Add(time.Millisecond) // nothing to do; idle forward
			} else {
				continue
			}
		}
		sim.clock.Advance(next.Sub(sim.now()))
		sim.deliver()
	}
}

// throughput is the average delivery rate over the simulated run.
func (sim *bbrSim) throughput(d time.Duration) Bandwidth {
	return BandwidthFromDelta(sim.delivered, d)
}

// TestBBRConvergesOnCleanPath is the end-to-end check that the control loop
// closes: with pacing, cwnd, and the model all wired together, a BBR flow on an
// uncongested bottleneck should discover roughly the link rate and hold an RTT
// close to the propagation delay.
func TestBBRConvergesOnCleanPath(t *testing.T) {
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	const minRTT = 50 * time.Millisecond
	bdp := bandwidthToBytes(bw, minRTT)

	sim := newBBRSim(t, bbrTestPath{bw: bw, minRTT: minRTT, bufferBytes: 4 * bdp})
	const duration = 20 * time.Second
	sim.run(duration)

	require.True(t, sim.sender.fullBWReached, "the flow should have left Startup")
	require.True(t, sim.sender.mode.isProbeBW() || sim.sender.mode == bbrProbeRTT,
		"expected a steady state, got %s", sim.sender.mode)

	got := sim.throughput(duration)
	require.InEpsilon(t, float64(bw), float64(got), 0.25,
		"throughput %d bps should be within 25%% of the %d bps link", got, bw)

	// BBR's whole point: hold the operating point near the BDP rather than
	// filling the buffer. Allow generous slack for ProbeBW_UP overshoot.
	require.Less(t, sim.sender.minRTT, 2*minRTT,
		"min_rtt %v should stay near the %v propagation delay", sim.sender.minRTT, minRTT)
}

// TestBBRToleratesRandomLoss is the property that motivates BBR for lossy paths:
// a 2% random loss rate collapses Reno's window, but should barely move BBR,
// because loss below LossThresh is not a congestion signal.
func TestBBRToleratesRandomLoss(t *testing.T) {
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	const minRTT = 50 * time.Millisecond
	bdp := bandwidthToBytes(bw, minRTT)

	sim := newBBRSim(t, bbrTestPath{
		bw: bw, minRTT: minRTT, bufferBytes: 4 * bdp, randomLoss: 0.02,
	})
	const duration = 20 * time.Second
	sim.run(duration)

	require.Positive(t, sim.lost, "the path should actually have dropped packets")
	got := sim.throughput(duration)
	require.Greater(t, float64(got), 0.5*float64(bw),
		"with 2%% random loss, throughput %d bps should stay above half the %d bps link", got, bw)
}

// TestBBRShallowBufferDoesNotCollapse checks the other half of the motivation: a
// buffer far smaller than the BDP causes congestive loss, and BBR should settle
// rather than ratchet the window to the floor.
func TestBBRShallowBufferDoesNotCollapse(t *testing.T) {
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	const minRTT = 50 * time.Millisecond

	sim := newBBRSim(t, bbrTestPath{
		bw: bw, minRTT: minRTT, bufferBytes: 8 * maxDatagramSize,
	})
	const duration = 20 * time.Second
	sim.run(duration)

	got := sim.throughput(duration)
	require.Greater(t, float64(got), 0.4*float64(bw),
		"throughput %d bps collapsed on a shallow buffer", got)
	require.GreaterOrEqual(t, sim.sender.GetCongestionWindow(), sim.sender.minCwnd())
}

// newRenoSim builds the same simulated path driven by quic-go's stock Reno
// sender, so BBR can be compared against the controller it replaces.
func newRenoSim(t *testing.T, path bbrTestPath) *bbrSim {
	t.Helper()
	clock := mockClock(monotime.Time(0).Add(simBase))
	rttStats := utils.NewRTTStats()
	return &bbrSim{
		clock:      &clock,
		rttStats:   rttStats,
		path:       path,
		rng:        rand.New(rand.NewPCG(1, 2)),
		linkFreeAt: clock.Now(),
		alt: newCubicSender(&clock, rttStats, &utils.ConnectionStats{}, true,
			maxDatagramSize, bbrInitialCwndPackets*maxDatagramSize,
			protocol.MaxCongestionWindowPackets*maxDatagramSize, nil),
	}
}

// TestBBRBeatsRenoUnderRandomLoss is the property that motivates replacing Reno.
// Reno reads every loss as congestion and halves its window, so a path with
// random loss pins it near the minimum window. BBR treats loss below LossThresh
// as noise and keeps sending at the measured delivery rate.
func TestBBRBeatsRenoUnderRandomLoss(t *testing.T) {
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	const duration = 30 * time.Second

	for _, tc := range []struct {
		name    string
		minRTT  time.Duration
		loss    float64
		minGain float64 // BBR must deliver at least this multiple of Reno
	}{
		{"50ms/5%", 50 * time.Millisecond, 0.05, 2.0},
		{"165ms/5%", 165 * time.Millisecond, 0.05, 2.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := bbrTestPath{
				bw:          bw,
				minRTT:      tc.minRTT,
				bufferBytes: 4 * bandwidthToBytes(bw, tc.minRTT),
				randomLoss:  tc.loss,
			}
			bbr := newBBRSim(t, path)
			bbr.run(duration)
			reno := newRenoSim(t, path)
			reno.run(duration)

			require.Positive(t, reno.delivered, "test setup: Reno must deliver something")
			require.Greater(t, float64(bbr.delivered), tc.minGain*float64(reno.delivered),
				"BBR delivered %d bytes, Reno %d: expected at least %.1fx",
				bbr.delivered, reno.delivered, tc.minGain)
		})
	}
}

// TestBBRHoldsShorterQueueThanReno is the other half of the motivation: on a
// deep-buffered path Reno fills the buffer before it sees loss, so its RTT grows
// to the buffer depth. BBR targets the BDP and leaves the buffer mostly empty,
// which is what keeps latency low for a live media flow.
func TestBBRHoldsShorterQueueThanReno(t *testing.T) {
	const bw = 10 * 1000 * 1000 * BitsPerSecond
	const minRTT = 100 * time.Millisecond
	const duration = 30 * time.Second

	// A buffer many times the BDP: the classic bufferbloated access link.
	path := bbrTestPath{
		bw:          bw,
		minRTT:      minRTT,
		bufferBytes: 10 * bandwidthToBytes(bw, minRTT),
	}
	bbr := newBBRSim(t, path)
	bbr.run(duration)
	reno := newRenoSim(t, path)
	reno.run(duration)

	require.Less(t, bbr.maxRTT, reno.maxRTT,
		"BBR peak RTT %v should be below Reno's %v on a deep buffer", bbr.maxRTT, reno.maxRTT)
	// BBR should not be parking multiples of the BDP in the buffer.
	require.Less(t, bbr.maxRTT, 3*minRTT,
		"BBR peak RTT %v should stay within a small multiple of the %v propagation delay",
		bbr.maxRTT, minRTT)
}

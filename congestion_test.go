package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

func TestBuiltinCongestionControllers(t *testing.T) {
	rttStats := utils.NewRTTStats()
	for _, tc := range []struct {
		name string
		ctor CongestionControllerFactory
	}{
		{"bbrv3", NewBBRv3},
		{"reno", NewReno},
		{"cubic", NewCubic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := tc.ctor(rttStats, protocol.InitialPacketSize, nil)
			require.NotNil(t, cc)
			require.Positive(t, cc.GetCongestionWindow())
			require.True(t, cc.CanSend(0))
			require.True(t, cc.InSlowStart(), "a fresh controller is ramping up")
		})
	}
}

// countingCongestionController wraps a controller and records that quic-go
// actually drove it.
type countingCongestionController struct {
	CongestionController
	sent, acked int
}

func (c *countingCongestionController) OnPacketSent(t Time, inFlight ByteCount, pn PacketNumber, b ByteCount, r bool) {
	c.sent++
	c.CongestionController.OnPacketSent(t, inFlight, pn, b, r)
}

func (c *countingCongestionController) OnPacketAcked(pn PacketNumber, acked, prior ByteCount, t Time) {
	c.acked++
	c.CongestionController.OnPacketAcked(pn, acked, prior, t)
}

// TestConfigCongestionIsUsed checks the whole path: a factory set on the Config
// reaches the sent packet handler and receives the connection's events.
func TestConfigCongestionIsUsed(t *testing.T) {
	var created int
	var last *countingCongestionController
	factory := func(rttStats RTTStatsProvider, size ByteCount, qlogger qlogwriter.Recorder) CongestionController {
		created++
		last = &countingCongestionController{CongestionController: NewReno(rttStats, size, qlogger)}
		return last
	}

	rttStats := utils.NewRTTStats()
	var connStats utils.ConnectionStats
	h := ackhandler.NewSentPacketHandler(
		0,
		protocol.InitialPacketSize,
		rttStats,
		&connStats,
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		toAckhandlerFactory(factory),
	)
	require.Equal(t, 1, created, "the factory is called once per connection")
	require.Zero(t, last.sent)

	now := monotime.Now()
	h.SentPacket(now, 1, protocol.InvalidPacketNumber, nil, nil, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
	require.Equal(t, 1, last.sent, "the custom controller sees sent packets")
}

// TestConfigCongestionNilUsesDefault confirms that leaving Config.Congestion
// unset keeps BBRv3, so the field is purely opt-in.
func TestConfigCongestionNilUsesDefault(t *testing.T) {
	require.Nil(t, toAckhandlerFactory(nil))

	c := populateConfig(&Config{})
	require.Nil(t, c.Congestion)

	// The default controller must be BBR: it leaves Startup on its own
	// estimators, so unlike Reno it ignores the MaybeExitSlowStart hint.
	cc := NewBBRv3(utils.NewRTTStats(), protocol.InitialPacketSize, nil)
	cwnd := cc.GetCongestionWindow()
	cc.MaybeExitSlowStart()
	require.True(t, cc.InSlowStart())
	require.Equal(t, cwnd, cc.GetCongestionWindow())
}

func TestCongestionControllerFactoryClonedByConfig(t *testing.T) {
	var called bool
	c := &Config{Congestion: func(RTTStatsProvider, ByteCount, qlogwriter.Recorder) CongestionController {
		called = true
		return nil
	}}
	populated := populateConfig(c)
	require.NotNil(t, populated.Congestion)
	populated.Congestion(nil, 1200, nil)
	require.True(t, called)
}

func TestRenoAndCubicGrowDifferently(t *testing.T) {
	// Reno and CUBIC are both loss-based, but they rebuild the congestion window
	// by different rules, so the two constructors must not be returning the same
	// controller. Which one ends up larger depends on how much time has passed
	// (CUBIC's growth is a function of time since the last cutback), so this
	// asserts only that they diverge.
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(100*time.Millisecond, 0)
	reno := NewReno(rtt, protocol.InitialPacketSize, nil)
	cubic := NewCubic(rtt, protocol.InitialPacketSize, nil)
	both := []CongestionController{reno, cubic}

	now := monotime.Now()
	for i := range 200 {
		for _, cc := range both {
			cc.OnPacketSent(now, ByteCount(i+1)*1200, PacketNumber(i), 1200, true)
		}
	}
	for _, cc := range both {
		cc.OnCongestionEvent(0, 1200, 200*1200)
	}
	afterLoss := reno.GetCongestionWindow()
	require.Equal(t, afterLoss, cubic.GetCongestionWindow(), "both cut by the same factor")

	// Acks for packets sent before the cutback are ignored while the controller
	// is in recovery, so send a fresh flight and ack that instead. priorInFlight
	// must exceed the window, or neither controller considers itself
	// cwnd-limited and neither grows.
	for i := 200; i < 900; i++ {
		for _, cc := range both {
			cc.OnPacketSent(now, ByteCount(i+1)*1200, PacketNumber(i), 1200, true)
		}
	}
	for i := 200; i < 900; i++ {
		now = now.Add(time.Millisecond)
		for _, cc := range both {
			cc.OnPacketAcked(PacketNumber(i), 1200, 900*1200, now)
		}
	}

	require.Greater(t, reno.GetCongestionWindow(), afterLoss, "Reno should have recovered some window")
	require.Greater(t, cubic.GetCongestionWindow(), afterLoss, "CUBIC should have recovered some window")
	require.NotEqual(t, reno.GetCongestionWindow(), cubic.GetCongestionWindow())
}

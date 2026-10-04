package tunnel

import "testing"

func TestStatsAccounting(t *testing.T) {
	var s Stats

	s.tcpOpened()
	s.tcpOpened()
	s.tcpClosed()
	s.udpOpened()
	s.dnsQuery()
	s.drop()
	s.addUp(1200)
	s.addDown(3400)
	s.addUp(-5) // 负数应被忽略
	s.addDown(0)

	got := s.Snapshot()
	want := Snapshot{
		TCPActive: 1, UDPActive: 1,
		TCPTotal: 2, UDPTotal: 1, DNSTotal: 1, Dropped: 1,
		BytesUp: 1200, BytesDown: 3400,
	}
	if got != want {
		t.Errorf("统计不符\n got  %+v\n want %+v", got, want)
	}
}

func TestNilStatsIsSafe(t *testing.T) {
	var s *Stats
	// 未启用统计时所有方法都应是空操作，不得 panic。
	s.tcpOpened()
	s.tcpClosed()
	s.udpOpened()
	s.udpClosed()
	s.dnsQuery()
	s.drop()
	s.addUp(1)
	s.addDown(1)
	if got := s.Snapshot(); got != (Snapshot{}) {
		t.Errorf("nil Stats 的快照应为零值，实际 %+v", got)
	}
}

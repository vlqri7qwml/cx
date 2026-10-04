package tunnel

import "sync/atomic"

// Stats 记录运行期流量与连接数，供托盘显示。
type Stats struct {
	tcpActive atomic.Int64
	udpActive atomic.Int64
	tcpTotal  atomic.Uint64
	udpTotal  atomic.Uint64
	dnsTotal  atomic.Uint64
	dropped   atomic.Uint64
	up        atomic.Uint64
	down      atomic.Uint64
}

// Snapshot 是某一时刻的统计快照。
type Snapshot struct {
	TCPActive int64  `json:"tcp_active"`
	UDPActive int64  `json:"udp_active"`
	TCPTotal  uint64 `json:"tcp_total"`
	UDPTotal  uint64 `json:"udp_total"`
	DNSTotal  uint64 `json:"dns_total"`
	Dropped   uint64 `json:"dropped"`
	BytesUp   uint64 `json:"bytes_up"`
	BytesDown uint64 `json:"bytes_down"`
}

// Snapshot 读取当前统计值。
func (s *Stats) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{
		TCPActive: s.tcpActive.Load(),
		UDPActive: s.udpActive.Load(),
		TCPTotal:  s.tcpTotal.Load(),
		UDPTotal:  s.udpTotal.Load(),
		DNSTotal:  s.dnsTotal.Load(),
		Dropped:   s.dropped.Load(),
		BytesUp:   s.up.Load(),
		BytesDown: s.down.Load(),
	}
}

func (s *Stats) tcpOpened() {
	if s != nil {
		s.tcpActive.Add(1)
		s.tcpTotal.Add(1)
	}
}

func (s *Stats) tcpClosed() {
	if s != nil {
		s.tcpActive.Add(-1)
	}
}

func (s *Stats) udpOpened() {
	if s != nil {
		s.udpActive.Add(1)
		s.udpTotal.Add(1)
	}
}

func (s *Stats) udpClosed() {
	if s != nil {
		s.udpActive.Add(-1)
	}
}

func (s *Stats) dnsQuery() {
	if s != nil {
		s.dnsTotal.Add(1)
	}
}

func (s *Stats) drop() {
	if s != nil {
		s.dropped.Add(1)
	}
}

func (s *Stats) addUp(n int) {
	if s != nil && n > 0 {
		s.up.Add(uint64(n))
	}
}

func (s *Stats) addDown(n int) {
	if s != nil && n > 0 {
		s.down.Add(uint64(n))
	}
}

package keysource

import (
	"sync"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type hiveConn struct {
	transport.StreamConn

	eventTemplate KeyEvent
	source        Source
	key           *Key

	totalUpstream      int64
	totalDownstream    int64
	recordedUpstream   int64
	recordedDownstream int64
	mu                 sync.Mutex
}

func (c *hiveConn) SendEvent() {
	c.mu.Lock()
	ev := c.eventTemplate
	ev.Upstream = c.totalUpstream - c.recordedUpstream
	ev.Downstream = c.totalDownstream - c.recordedDownstream
	ev.Timestamp = time.Now().Unix()
	// Include connection count only for the first event sent
	if c.recordedUpstream+c.recordedDownstream == 0 {
		ev.Count = 1
	} else {
		ev.Count = 0
	}
	c.recordedUpstream = c.totalUpstream
	c.recordedDownstream = c.totalDownstream
	c.mu.Unlock()

	c.source.SendEvent(ev)
}

func (c *hiveConn) Incr(upstream, downstream int64) {
	c.mu.Lock()
	c.totalUpstream += upstream
	c.totalDownstream += downstream
	totalTraffic := c.totalUpstream + c.totalDownstream
	totalRecordedTraffic := c.recordedUpstream + c.recordedDownstream
	c.mu.Unlock()

	if totalTraffic-totalRecordedTraffic > 100000000 { // ~ 100 MB
		c.SendEvent()
	}

	if c.key.State == StateSuspend || (c.key.State == StateProbation && totalTraffic >= ProbationAllowance) {
		c.StreamConn.Close()
	}
}

func (c *hiveConn) Read(b []byte) (int, error) {
	n, err := c.StreamConn.Read(b)
	c.Incr(int64(n), 0)
	return n, err
}

func (c *hiveConn) Write(b []byte) (int, error) {
	n, err := c.StreamConn.Write(b)
	c.Incr(0, int64(n))
	return n, err
}

func (c *hiveConn) Close() error {
	c.SendEvent()
	return c.StreamConn.Close()
}

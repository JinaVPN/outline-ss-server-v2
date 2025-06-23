package key

import (
	"io"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type KeyState string
type TrafficOverusePolicy string

const (
	AddAction    = "add"
	RemoveAction = "remove"

	StateActive    KeyState = "active"
	StateProbation KeyState = "probation"
	StateSuspend   KeyState = "suspend"

	ProbationAllowance = 10000 // 10KB
)

type Key struct {
	ID            string   `json:"id"`
	Port          int      `json:"port"`
	Cipher        string   `json:"cipher"`
	Secret        string   `json:"secret"`
	State         KeyState `json:"state"`
	OverusePolicy KeyState `json:"overuse"`
}

type KeyCommand struct {
	Action string
	Key    Key
}

type KeyEvent struct {
	ID                   string `json:"id"`
	Event                string `json:"ev"`
	ASN                  int    `json:"asn"`
	Src                  string `json:"src"`
	Dst                  string `json:"dst"`
	DstPort              uint16 `json:"dst_port"`
	DstHost              string `json:"dst_host"`
	Downstream           int64  `json:"dn"`
	Upstream             int64  `json:"up"`
	Timestamp            int64  `json:"tm"`
	Count                int64  `json:"cn"`
	FastAuth             bool   `json:"fa"`
	CipherLookupTime     int64  `json:"clt"`
	CipherLookupAttempts int    `json:"cla"`
}

type Source interface {
	Channel() chan KeyCommand
	WrapConn(keyID string, writer onet.DuplexConn, reader io.Reader, eventTemplate KeyEvent) (onet.DuplexConn, io.Reader, func(socks.Addr, onet.DuplexConn))
	SendEvent(KeyEvent)
	Close() error
}

func MergeSources(sources []Source) chan KeyCommand {
	ch := make(chan KeyCommand)
	for _, s := range sources {
		c := s.Channel()
		go func() {
			for e := range c {
				ch <- e
			}
		}()
	}
	return ch
}

type Backoff struct {
	min     time.Duration
	max     time.Duration
	mult    int
	current time.Duration
}

func NewBackoff(min, max time.Duration, mult int) *Backoff {
	return &Backoff{
		min:     min,
		max:     max,
		mult:    mult,
		current: 0,
	}
}

func (b *Backoff) Wait() {
	time.Sleep(b.current)
}

func (b *Backoff) HasWait() bool {
	return b.current > 0
}

func (b *Backoff) Increase() {
	if b.current == 0 {
		b.current = b.min
		return
	}
	b.current = b.current * time.Duration(b.mult)
	if b.current > b.max {
		b.current = b.max
	}
}

func (b *Backoff) Reset() bool {
	isReset := b.current != 0
	b.current = 0
	return isReset
}

func (b *Backoff) Seconds() float64 {
	return b.current.Seconds()
}

package keysource

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	hive "github.com/Jigsaw-Code/outline-ss-server/keysource/hive"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type hiveSource struct {
	KeyUpdater

	hiveClient   hive.HiveClient
	enableEvents bool
	closeCh      chan bool

	eventsCh chan KeyEvent
	keys     map[uint64]*Key
	keysMu   sync.Mutex

	statsMu          sync.Mutex
	totalUpstream    uint64
	totalDownstream  uint64
	totalConnections uint64
	eventsDropped    uint64
	keysAdded        uint32
	keysRemoved      uint32
	eventReqAttempts uint32
	eventReqSuccess  uint32
	eventReqFail     uint32

	addLog    *aggregateLogger
	updateLog *aggregateLogger
	removeLog *aggregateLogger
	dropLog   *aggregateLogger
}

func NewHiveSource(hiveURL, hiveSecret string, enableEvents, isInsecure bool) Source {
	hostname, _ := os.Hostname()

	var creds credentials.TransportCredentials
	if isInsecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewClientTLSFromCert(nil, "")
	}

	conn, err := grpc.Dial(hiveURL,
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			ctx = metadata.AppendToOutgoingContext(ctx,
				"Hive-Secret", hiveSecret,
				"Hive-Server", hostname,
			)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
		grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			ctx = metadata.AppendToOutgoingContext(ctx,
				"Hive-Secret", hiveSecret,
				"Hive-Server", hostname,
			)
			clientStream, err := streamer(ctx, desc, cc, method, opts...)
			return clientStream, err
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    60 * time.Second,
			Timeout: 120 * time.Second,
		}),
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(`{
			"methodConfig": [{
				"name": [{"service": "hive.Hive"}],
				"retryPolicy": {
					"maxAttempts": 1,
					"initialBackoff": "0.1s",
					"maxBackoff": "0.1s",
					"backoffMultiplier": 1.0,
					"retryableStatusCodes": []
				}
			}]
		}`),
	)
	if err != nil {
		slog.Error(err.Error())
		return nil
	}

	s := &hiveSource{
		hiveClient:   hive.NewHiveClient(conn),
		enableEvents: enableEvents,
		closeCh:      make(chan bool),
		keys:         make(map[uint64]*Key),
		eventsCh:     make(chan KeyEvent, 1000000),

		addLog:    NewAggregateLogger(time.Second, 100, "Added %d access keys"),
		updateLog: NewAggregateLogger(time.Second, 100, "Updated %d access keys"),
		removeLog: NewAggregateLogger(time.Second, 100, "Removed %d access keys"),
		dropLog:   NewAggregateLogger(5*time.Second, 10, "Dropped %d access key events due to full channel"),
	}
	go s.sendReports()
	if s.enableEvents {
		go s.publishEvents()
	}
	return s
}

func (h *hiveSource) Register(cipherList service.CipherList) error {
	h.KeyUpdater = KeyUpdater{
		Ciphers:     cipherList,
		ciphersByID: make(map[string]func()),
	}
	return nil
}

func (s *hiveSource) Channel() chan KeyCommand {
	ctx, cancel := context.WithCancel(context.Background())

	keyCmdCh := make(chan KeyCommand)
	hiveKeyCh := make(chan *hive.AccessKeysResponse)

	backoff := NewBackoff(time.Second, 60*time.Second, 2)
	backoff.Increase()
	wg := sync.WaitGroup{}

	go func() {
		<-s.closeCh
		cancel()
		wg.Wait()
		close(keyCmdCh)
		close(hiveKeyCh)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				s.readKeysFromHive(ctx, backoff, hiveKeyCh)
				slog.Info("AccessKey stream backing off", "seconds", backoff.Seconds())
				backoff.Wait()
				slog.Info("Retrying watching keys on hive")
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-hiveKeyCh:
				s.handleKeyFromHive(r, keyCmdCh)
			}
		}
	}()

	go s.logActiveKeys(ctx)

	return keyCmdCh
}

func (s *hiveSource) readKeysFromHive(ctx context.Context, backoff *Backoff, ch chan *hive.AccessKeysResponse) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resp, err := s.hiveClient.AccessKeys(ctx, &hive.AccessKeysRequest{})
	if err != nil {
		slog.Error("Error watching access keys on hive", "error", err)
		backoff.Increase()
		return
	}

	for {
		msg, err := resp.Recv()
		if err != nil {
			slog.Error("Error receiving access key from hive", "error", err)
			backoff.Increase()
			return
		}
		if backoff.Reset() {
			slog.Info("AccessKey stream established")
		}

		// Write to the channel, unless the context is closed.
		select {
		case <-ctx.Done():
			return
		case ch <- msg:
		}
	}
}
func (s *hiveSource) handleKeyFromHive(r *hive.AccessKeysResponse, ch chan KeyCommand) {
	k := Key{
		ID:            fmt.Sprintf("%d", r.AccessKey.Id),
		Port:          int(r.AccessKey.Port),
		Cipher:        r.AccessKey.Cipher,
		Secret:        r.AccessKey.Secret,
		State:         s.parseKeyState(r.AccessKey.State),
		OverusePolicy: s.parseKeyState(r.AccessKey.OverusePolicy),
	}

	var cmd *KeyCommand
	kid := r.AccessKey.Id

	s.keysMu.Lock()
	switch r.Action {
	case hive.AccessKeyAction_ACTION_ADD:
		if _, exists := s.keys[kid]; !exists {
			cmd = &KeyCommand{Action: AddAction, Key: k}
			s.keys[kid] = &k
			s.addLog.Log("Adding key %s with status '%s'", k.ID, k.State)

			s.statsMu.Lock()
			s.keysAdded += 1
			s.statsMu.Unlock()
		} else if s.keys[kid].State != k.State {
			// Updating existing key reference so that wrapped connections will pick up the new state.
			*s.keys[kid] = k
			s.updateLog.Log("Updating key %s with status '%s'", k.ID, k.State)
		}
	case hive.AccessKeyAction_ACTION_REMOVE:
		if _, exists := s.keys[kid]; exists {
			cmd = &KeyCommand{Action: RemoveAction, Key: k}
			delete(s.keys, kid)
			s.removeLog.Log("Removing key %s", k.ID)
		}
		s.statsMu.Lock()
		s.keysRemoved += 1
		s.statsMu.Unlock()
	}
	s.keysMu.Unlock()

	if cmd != nil {
		ch <- *cmd
	}
}

func (s *hiveSource) parseKeyState(ks hive.AccessKeyState) KeyState {
	switch ks {
	case hive.AccessKeyState_STATE_ACTIVE:
		return StateActive
	case hive.AccessKeyState_STATE_SUSPEND:
		return StateSuspend
	case hive.AccessKeyState_STATE_PROBATION:
		return StateProbation
	default:
		slog.Error("Invalid key state received from hive", "keyState", ks)
		return StateActive
	}
}

func (s *hiveSource) logActiveKeys(ctx context.Context) {
	ticker := time.NewTicker(360 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		s.keysMu.Lock()
		slog.Info("Serving keys", "count", len(s.keys))
		s.keysMu.Unlock()
	}
}

func (s *hiveSource) SendEvent(e KeyEvent) {
	s.statsMu.Lock()
	s.totalUpstream = s.totalUpstream + uint64(e.Upstream)
	s.totalDownstream = s.totalDownstream + uint64(e.Downstream)
	s.totalConnections = s.totalConnections + uint64(e.Count)
	s.statsMu.Unlock()

	if !s.enableEvents {
		return
	}

	select {
	case s.eventsCh <- e:
	default:
		s.dropLog.Log("Dropping event due to full channel")
		s.statsMu.Lock()
		s.eventsDropped += 1
		s.statsMu.Unlock()
	}
}

func (s *hiveSource) sendReports() {
	ticker := time.NewTicker(time.Second * 30)

loop:
	for {
		select {
		case <-s.closeCh: // Handle close after we've drained the events channel
			break loop
		case <-ticker.C:
		}

		s.keysMu.Lock()
		keyCount := len(s.keys)
		s.keysMu.Unlock()

		s.statsMu.Lock()
		r := &hive.HandleReportRequest{
			TotalUpstream:    uint64(s.totalUpstream),
			TotalDownstream:  uint64(s.totalDownstream),
			TotalConnections: uint64(s.totalConnections),
			EventsBuffered:   uint32(len(s.eventsCh)),
			EventsDropped:    s.eventsDropped,
			KeyCount:         uint32(keyCount),
			KeysAdded:        uint32(s.keysAdded),
			KeysRemoved:      uint32(s.keysRemoved),
			EventReqAttempts: s.eventReqAttempts,
			EventReqSuccess:  s.eventReqSuccess,
			EventReqFail:     s.eventReqFail,
		}
		s.statsMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		_, err := s.hiveClient.HandleReport(ctx, r)
		if err != nil {
			slog.Error("Failed sending report to hive", "error", err)
		}
	}
}

func (s *hiveSource) publishEvents() {
	ctx := context.Background()
	batchSize := 4000

	backoff := NewBackoff(time.Millisecond*500, time.Second*30, 2)
	events := make(map[string]KeyEvent, batchSize)
	ticker := time.NewTicker(time.Second * 10)
	seq := uint64(0)
	skipTick := false

loop:
	for {
		select {
		case e := <-s.eventsCh:
			kid := fmt.Sprintf("%s#%s", e.ID, e.Src)

			if ev, ok := events[kid]; !ok {
				events[kid] = e
			} else {
				ev.Upstream += e.Upstream
				ev.Downstream += e.Downstream
				ev.Count += e.Count
				events[kid] = ev
			}

			if len(events) < batchSize {
				continue
			}
			skipTick = true
		case <-s.closeCh: // Handle close after we've drained the events channel
			break loop
		case <-ticker.C:
			if skipTick {
				skipTick = false
				continue
			}
		}

		if len(events) > 0 {
			// Will block until all events are sent (with exponential backoff)
			s.sendEventsToHive(ctx, seq, backoff, events)

			seq += 1
			events = make(map[string]KeyEvent, batchSize)
		}
	}

	if len(events) > 0 {
		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()
		s.sendEventsToHive(ctx, seq, backoff, events)
	}
}

func (s *hiveSource) sendEventsToHive(ctx context.Context, seq uint64, backoff *Backoff, events map[string]KeyEvent) {
	hiveEvents := make([]*hive.ConnectionEvent, 0, len(events))
	downstream := int64(0)
	upstream := int64(0)
	keySet := make(map[uint64]any)
	for _, e := range events {
		kid, err := strconv.ParseUint(e.ID, 10, 64)
		if err != nil {
			slog.Error("Non int key IDs are not supported on hive", "id", e.ID)
			continue
		}

		hiveEvents = append(hiveEvents, &hive.ConnectionEvent{
			Event: 0,
			KeyId: kid,
			Src:   e.Src,
			// Dst:                  e.Dst,
			// DstPort:              uint32(e.DstPort),
			// DstHost:              e.DstHost,
			Downstream:           uint64(e.Downstream),
			Upstream:             uint64(e.Upstream),
			Timestamp:            uint64(e.Timestamp),
			ConnectionCount:      uint32(e.Count),
			FastAuth:             e.FastAuth,
			CipherLookupTime:     uint32(e.CipherLookupTime),
			CipherLookupAttempts: uint32(e.CipherLookupAttempts),
		})
		downstream = downstream + e.Downstream
		upstream = upstream + e.Upstream
		keySet[kid] = nil
	}

	msg := &hive.HandleEventsRequest{
		Seq:    seq,
		Events: hiveEvents,
	}
	msgSize := int64(proto.Size(msg))

	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.statsMu.Lock()
		s.eventReqAttempts += 1
		s.statsMu.Unlock()

		if attempt > 0 {
			slog.Info(fmt.Sprintf("Sending events to hive [seq=%d] [count=%d] [size=%s] [attempt %d]", seq, len(hiveEvents), byteCountSI(msgSize), attempt+1))
		} else {
			slog.Info(fmt.Sprintf("Sending events to hive [seq=%d] [count=%d] [keys=%d] [size=%s] [up=%s] [down=%s]", seq, len(hiveEvents), len(keySet), byteCountSI(msgSize), byteCountSI(upstream), byteCountSI(downstream)))
		}

		err := func() error {
			ctx, cancel := context.WithTimeout(ctx, time.Second*10)
			defer cancel()
			_, err := s.hiveClient.HandleEvents(ctx, msg)
			return err
		}()

		if err != nil {
			backoff.Increase()
			slog.Error(fmt.Sprintf("Failed sending events to hive [seq=%d], backing off for %v: %v", seq, backoff.Seconds(), err))
			backoff.Wait()
			attempt += 1

			s.statsMu.Lock()
			s.eventReqFail += 1
			s.statsMu.Unlock()
			continue
		}

		s.statsMu.Lock()
		s.eventReqSuccess += 1
		s.statsMu.Unlock()

		backoff.Reset()
		return
	}
}

func (s *hiveSource) Close() error {
	close(s.closeCh)
	close(s.eventsCh)
	return nil
}

func (s *hiveSource) WrapConn(keyID string, writer transport.StreamConn, eventTemplate KeyEvent) (transport.StreamConn, func(socks.Addr, transport.StreamConn)) {
	kid, err := strconv.ParseUint(keyID, 10, 64)
	if err != nil {
		return writer, nil
	}

	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	key := s.keys[kid]

	if key.State == StateSuspend {
		slog.Info("Rejecting connection on suspended key", "kid", kid)
		writer.Close()
		return writer, nil
	}

	c := &hiveConn{
		StreamConn:    writer,
		eventTemplate: eventTemplate,
		source:        s,
		key:           key,
	}

	setDestination := func(dst socks.Addr, conn onet.DuplexConn) {
		c.mu.Lock()
		defer c.mu.Unlock()

		if len(dst) > 0 && dst[0] == socks.AtypDomainName {
			dstAddr := dst.String()
			if utf8.ValidString(dstAddr) {
				c.eventTemplate.DstHost = strings.Split(dstAddr, ":")[0]
			}
		}
		addr := conn.RemoteAddr()
		if addr != nil {
			ipstr, port, err := net.SplitHostPort(addr.String())
			if err == nil {
				c.eventTemplate.Dst = ipstr
				p, _ := strconv.ParseInt(port, 10, 16)
				c.eventTemplate.DstPort = uint16(p)
			}
		}
	}

	return c, setDestination
}

type aggregateLogger struct {
	aggMsg   string
	maxCnt   int
	interval time.Duration
	messages []string
	count    int
	mu       sync.Mutex
	timer    *time.Timer
}

func NewAggregateLogger(interval time.Duration, maxCnt int, aggMsg string) *aggregateLogger {
	return &aggregateLogger{
		interval: interval,
		aggMsg:   aggMsg,
		maxCnt:   maxCnt,
		messages: make([]string, 0, maxCnt),
	}
}

func (l *aggregateLogger) Log(msg string, args ...any) {
	defer l.trigger()

	l.mu.Lock()
	l.count += 1
	if len(l.messages) < l.maxCnt {
		l.messages = append(l.messages, fmt.Sprintf(msg, args...))
	}
	l.mu.Unlock()
}

func (l *aggregateLogger) trigger() {
	l.mu.Lock()
	if l.timer == nil {
		l.timer = time.NewTimer(l.interval)
		go func() {
			<-l.timer.C
			l.periodicLog()
		}()
	}
	l.mu.Unlock()
}

func (l *aggregateLogger) periodicLog() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.messages) < l.maxCnt {
		for _, m := range l.messages {
			slog.Info(m)
		}
	} else if l.count > 0 {
		slog.Info(fmt.Sprintf(l.aggMsg, l.count))
	}
	l.count = 0
	l.messages = l.messages[:0]
	l.timer = nil
}

func byteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

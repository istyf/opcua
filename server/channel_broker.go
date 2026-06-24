package server

import (
	"context"
	"crypto/rsa"
	"errors"
	"io"
	mrand "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

const defaultChannelBrokerCloseTimeout = 10 * time.Second

func isExpectedChannelShutdownError(err error) bool {
	if err == nil {
		return false
	}

	if err == io.EOF || err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}

	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed network connection")
}

func sendSecureChannelError(conn *uacp.Conn, err error) {
	status, ok := err.(ua.StatusCode)
	if !ok {
		return
	}
	conn.SendError(status)
}

type channelBroker struct {
	endpoints map[string]*ua.EndpointDescription

	wg sync.WaitGroup

	// mu protects concurrent modification of s, secureChannelID, and secureTokenID
	mu sync.RWMutex
	// s is a slice of all SecureChannels watched by the channelBroker
	s map[uint32]*uasc.SecureChannel

	// Next Secure Channel ID to issue to a client
	secureChannelID uint32

	// Next Token ID to issue to a client
	secureTokenID uint32

	// msgChan is the common channel that all messages from all channels
	// get funneled into for handling
	msgChan chan *uasc.MessageBody
}

func newChannelBroker() *channelBroker {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &channelBroker{
		endpoints:       make(map[string]*ua.EndpointDescription),
		s:               make(map[uint32]*uasc.SecureChannel),
		msgChan:         make(chan *uasc.MessageBody),
		secureChannelID: uint32(rng.Int31()),
		secureTokenID:   uint32(rng.Int31()),
	}
}

func (c *channelBroker) enqueueMessage(ctx context.Context, msg *uasc.MessageBody) bool {
	select {
	case <-ctx.Done():
		return false
	case c.msgChan <- msg:
		return true
	}
}

func (c *channelBroker) CloseSecureChannel(ctx context.Context, id uint32) bool {
	c.mu.RLock()
	sc, ok := c.s[id]
	c.mu.RUnlock()
	if !ok || sc == nil {
		return false
	}

	_ = sc.CloseWithContext(ctx)
	return true
}

func validateEnabledSecureChannelPolicy(enabled []security) func(string) error {
	return func(policy string) error {
		for _, sec := range enabled {
			if sec.secPolicy.URI() == policy {
				return nil
			}
		}
		return ua.StatusBadSecurityPolicyRejected
	}
}

func validateEnabledSecureChannelMode(enabled []security) func(string, ua.MessageSecurityMode) error {
	return func(policy string, mode ua.MessageSecurityMode) error {
		for _, sec := range enabled {
			if sec.secPolicy.URI() == policy && sec.secMode == mode {
				return nil
			}
		}
		return ua.StatusBadSecurityModeRejected
	}
}

// RegisterConn connects a new UACP connection to the channel broker's list
// of connections and starts waiting for data on it.  Data is pushed onto the broker's
// Response channel
// Blocks until the context is done, the connection closes, or a critical error
func (c *channelBroker) RegisterConn(ctx context.Context, endpoint string, conn *uacp.Conn, localCert []byte, advertisedCert []byte, localKey *rsa.PrivateKey, enabled []security) error {
	cfg := defaultChannelConfig()
	cfg.Certificate = localCert
	cfg.AdvertisedCertificate = advertisedCert
	cfg.LocalKey = localKey
	cfg.ServerSecurityPolicyValidator = validateEnabledSecureChannelPolicy(enabled)
	cfg.ServerOpenSecureChannelValidator = validateEnabledSecureChannelMode(enabled)

	c.mu.Lock()
	c.secureChannelID++
	c.secureTokenID++
	secureChannelID := c.secureChannelID
	secureTokenID := c.secureTokenID
	sequenceNumber := uint32(mrand.Int31n(1023) + 1)
	c.mu.Unlock()

	errch := make(chan error, 1)
	sc, err := uasc.NewServerSecureChannel(
		endpoint,
		conn,
		cfg,
		errch,
		secureChannelID,
		sequenceNumber,
		secureTokenID,
	)
	if err != nil {
		ualog.Error(ctx, "could not create secure channel for new connection", err)
		return err
	}

	c.mu.Lock()
	c.s[secureChannelID] = sc
	channelCount := len(c.s)
	c.mu.Unlock()
	c.wg.Add(1)

	ctx = ualog.WithAttrs(ctx, ualog.Uint32("channel", secureChannelID))
	ualog.Info(ctx, "registered new channel", ualog.Int("count", channelCount))

outer:
	for {
		select {
		case <-ctx.Done():
			break outer

		default:
			msg := sc.Receive(ctx)
			if msg.Err == io.EOF {
				break outer
			} else if msg.Err != nil {
				if isExpectedChannelShutdownError(msg.Err) {
					_ = conn.Close()
					break outer
				}
				sendSecureChannelError(conn, msg.Err)
				_ = conn.Close()
				ualog.Error(ctx, "secure channel error", msg.Err)
				break outer
			}
			if !c.enqueueMessage(ctx, msg) {
				break outer
			}
		}
	}

	c.mu.Lock()
	delete(c.s, secureChannelID)
	c.mu.Unlock()
	c.wg.Done()

	return nil
}

// Close gracefully closes all secure channels.
func (c *channelBroker) Close(ctx context.Context, timeout time.Duration) error {
	var err error
	c.mu.Lock()
	for _, s := range c.s {
		_ = s.CloseWithContext(ctx)
	}
	c.mu.Unlock()

	// Wait for all goroutines to finish or timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.wg.Wait()
	}()

	if timeout <= 0 {
		timeout = defaultChannelBrokerCloseTimeout
	}

	select {
	case <-done:
	case <-time.After(timeout):
		ualog.Error(ctx, "error during shutdown",
			errors.New("timed out waiting for channels to exit"),
			ualog.Duration("timeout", timeout),
		)
	}

	return err
}

func (c *channelBroker) ReadMessage(ctx context.Context) *uasc.MessageBody {
	select {
	case <-ctx.Done():
		return nil
	case msg := <-c.msgChan:
		return msg
	}
}

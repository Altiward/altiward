// Package syslog sends RFC 5424 messages to a syslog receiver over TLS (RFC 5425) or plain
// TCP (RFC 6587). There is no UDP: a lost datagram would be a lost event, and Altiward
// never drops events.
//
// Syslog has no acknowledgement. Send returns nil once every byte is written and the
// connection closed cleanly, which is as close to delivery as the protocol gets; a failed
// batch is retried whole, so a receiver may see a message twice.
package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Framing separates messages on the stream.
type Framing int

const (
	// OctetCounting prefixes each message with its length (RFC 6587 3.4.1, RFC 5425).
	OctetCounting Framing = iota
	// Newline ends each message with LF, for receivers that only read lines. Messages
	// must not contain a newline.
	Newline
)

// Facilities and severities used by Altiward (RFC 5424 6.2.1).
const (
	FacilityAuthPriv = 10 // security and authorization messages

	SeverityError   = 3
	SeverityWarning = 4
	SeverityNotice  = 5
	SeverityInfo    = 6
)

// Message is one RFC 5424 message with no structured data.
type Message struct {
	Time     time.Time
	Facility int
	Severity int
	Hostname string // "-" when empty
	AppName  string // "-" when empty
	MsgID    string // "-" when empty
	Body     string
}

// String renders the message: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG.
func (m Message) String() string {
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s", m.Facility*8+m.Severity,
		m.Time.UTC().Format("2006-01-02T15:04:05.000Z"), field(m.Hostname, 255), field(m.AppName, 48), field(m.MsgID, 32), m.Body)
}

// field is a header field: printable US-ASCII without spaces, "-" when empty.
func field(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	if s == "" {
		return "-"
	}
	return s
}

// Client writes batches to one receiver, a fresh connection per batch.
type Client struct {
	Addr    string      // host:port
	TLS     *tls.Config // nil means plain TCP
	Framing Framing
	Timeout time.Duration // for connecting and for writing a batch; default 30s
}

// Send writes msgs in order on one connection.
func (c *Client) Send(ctx context.Context, msgs []Message) error {
	if len(msgs) == 0 {
		return nil
	}
	var buf strings.Builder
	for _, m := range msgs {
		s := m.String()
		switch c.Framing {
		case Newline:
			if strings.ContainsAny(s, "\r\n") {
				return errors.New("syslog: a message contains a newline, which newline framing can't carry")
			}
			buf.WriteString(s)
			buf.WriteByte('\n')
		default:
			buf.WriteString(strconv.Itoa(len(s)))
			buf.WriteByte(' ')
			buf.WriteString(s)
		}
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("syslog: connect %s: %w", c.Addr, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write([]byte(buf.String())); err != nil {
		return fmt.Errorf("syslog: write: %w", err)
	}
	// A clean close flushes TLS and tells the receiver the batch is complete.
	if err := conn.Close(); err != nil {
		return fmt.Errorf("syslog: close: %w", err)
	}
	return nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.TLS == nil {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", c.Addr)
	}
	cfg := c.TLS.Clone()
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			return nil, err
		}
		cfg.ServerName = host
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	d := tls.Dialer{Config: cfg}
	return d.DialContext(ctx, "tcp", c.Addr)
}

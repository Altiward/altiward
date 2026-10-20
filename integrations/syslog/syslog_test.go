package syslog_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/syslog"
)

var at = time.Date(2026, 10, 17, 9, 0, 0, 123_000_000, time.UTC)

func msg(body string) syslog.Message {
	return syslog.Message{Time: at, Facility: syslog.FacilityAuthPriv, Severity: syslog.SeverityWarning,
		Hostname: "altiward", AppName: "altiward", MsgID: "elevation.granted", Body: body}
}

func TestMessageFormat(t *testing.T) {
	got := msg("hello").String()
	want := "<84>1 2026-10-17T09:00:00.123Z altiward altiward - elevation.granted - hello"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	empty := syslog.Message{Time: at, Facility: syslog.FacilityAuthPriv, Severity: syslog.SeverityInfo, Hostname: "a b"}
	if got := empty.String(); got != "<86>1 2026-10-17T09:00:00.123Z ab - - - - " {
		t.Fatalf("empty fields: %q", got)
	}
}

// listen accepts one connection and returns everything it receives.
func listen(t *testing.T, ln net.Listener) <-chan string {
	t.Helper()
	out := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- "accept: " + err.Error()
			return
		}
		defer conn.Close()
		b, _ := io.ReadAll(conn)
		out <- string(b)
	}()
	t.Cleanup(func() { ln.Close() })
	return out
}

func TestOctetCountingOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := listen(t, ln)
	c := &syslog.Client{Addr: ln.Addr().String()}
	if err := c.Send(context.Background(), []syslog.Message{msg("one"), msg("two\nlines")}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(strings.NewReader(<-got))
	var bodies []string
	for {
		n, err := r.ReadString(' ')
		if err == io.EOF {
			break
		}
		size, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			t.Fatalf("frame length %q: %v", n, err)
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(r, b); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(b))
	}
	if len(bodies) != 2 || !strings.HasSuffix(bodies[0], " - one") || !strings.HasSuffix(bodies[1], " - two\nlines") {
		t.Fatalf("frames = %q", bodies)
	}
}

func TestNewlineFramingRefusesNewlines(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := listen(t, ln)
	c := &syslog.Client{Addr: ln.Addr().String(), Framing: syslog.Newline}
	if err := c.Send(context.Background(), []syslog.Message{msg("a"), msg("b")}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSuffix(<-got, "\n"), "\n"); len(lines) != 2 || !strings.HasSuffix(lines[1], " - b") {
		t.Fatalf("lines = %q", lines)
	}
	if err := c.Send(context.Background(), []syslog.Message{msg("x\ny")}); err == nil {
		t.Fatal("sent a newline in newline framing")
	}
}

func TestTLSVerifiesTheReceiver(t *testing.T) {
	cert, pool := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	got := listen(t, ln)
	c := &syslog.Client{Addr: ln.Addr().String(), TLS: &tls.Config{RootCAs: pool, ServerName: "syslog.test"}}
	if err := c.Send(context.Background(), []syslog.Message{msg("secure")}); err != nil {
		t.Fatal(err)
	}
	if body := <-got; !strings.HasSuffix(body, " - secure") {
		t.Fatalf("received %q", body)
	}

	// The system roots don't trust the test certificate.
	ln2, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	listen(t, ln2)
	untrusting := &syslog.Client{Addr: ln2.Addr().String(), TLS: &tls.Config{ServerName: "syslog.test"}, Timeout: 5 * time.Second}
	if err := untrusting.Send(context.Background(), []syslog.Message{msg("x")}); err == nil {
		t.Fatal("sent to a receiver whose certificate isn't trusted")
	}
}

func TestUnreachableReceiverIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	c := &syslog.Client{Addr: addr, Timeout: 2 * time.Second}
	if err := c.Send(context.Background(), []syslog.Message{msg("x")}); err == nil {
		t.Fatal("no error for a closed port")
	}
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "syslog.test"}, DNSNames: []string{"syslog.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

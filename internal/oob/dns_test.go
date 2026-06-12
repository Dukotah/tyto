package oob

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// buildQuery hand-assembles a standard A/IN query packet for name, with the given
// transaction id. This is the wire format the collaborator's DNS half must parse;
// building it by hand (no third-party lib) keeps the test honest about the bytes.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1, standard query
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	// AN/NS/AR counts stay zero.
	pkt := append([]byte{}, hdr[:]...)
	for _, label := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0) // root terminator
	var tc [4]byte
	binary.BigEndian.PutUint16(tc[0:2], qtype)
	binary.BigEndian.PutUint16(tc[2:4], dnsTypeIN)
	pkt = append(pkt, tc[:]...)
	return pkt
}

// parseFirstAnswer pulls the single A answer's IPv4 out of a response built by
// buildDNSResponse. It assumes our own wire layout (compression pointer name +
// 10-byte fixed RR head + 4-byte RDATA) and returns nil if there is no answer.
func parseFirstAnswer(t *testing.T, resp []byte, q dnsQuery) net.IP {
	t.Helper()
	if len(resp) < 12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount == 0 {
		return nil
	}
	// Header (12) + echoed question, then the answer RR.
	off := 12 + len(q.question)
	// NAME pointer(2) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 12 bytes of RR head.
	if off+12+4 > len(resp) {
		t.Fatalf("answer truncated")
	}
	rdlen := binary.BigEndian.Uint16(resp[off+10 : off+12])
	if rdlen != 4 {
		t.Fatalf("RDLENGTH = %d, want 4", rdlen)
	}
	rdata := resp[off+12 : off+16]
	return net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3])
}

// TestServeDNS_ParseAndAnswer drives the pure parse+build seam: register a token,
// hand handleDNSPacket a hand-built A query for "<token>.oob.example.com", and
// assert (a) a ProtoDNS hit was recorded and (b) the response echoes back the
// configured PublicHost IPv4.
func TestServeDNS_ParseAndAnswer(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com", PublicHost: "203.0.113.7"})
	it := c.Register("ssrf", "http://target.test/", "url")

	pkt := buildQuery(0x1234, it.Domain, dnsTypeA)
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 5353}

	resp, ok := c.handleDNSPacket(pkt, src)
	if !ok {
		t.Fatal("handleDNSPacket returned ok=false for a valid query")
	}

	// Hit recorded and correlated to the issued token.
	hits := c.Poll(it.Token)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	h := hits[0]
	if h.Proto != ProtoDNS {
		t.Errorf("hit proto = %q, want %q", h.Proto, ProtoDNS)
	}
	if h.Detail != "A "+it.Domain {
		t.Errorf("hit detail = %q, want %q", h.Detail, "A "+it.Domain)
	}
	if h.RemoteAddr != src.String() {
		t.Errorf("hit remote = %q, want %q", h.RemoteAddr, src.String())
	}

	// Response header sanity + A record points at PublicHost.
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Errorf("response ID not echoed")
	}
	if resp[2]&0x80 == 0 {
		t.Errorf("QR bit not set in response")
	}
	q, qok := parseDNSQuery(pkt)
	if !qok {
		t.Fatal("parseDNSQuery failed on a valid query")
	}
	got := parseFirstAnswer(t, resp, q)
	if got == nil || !got.Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("answer IP = %v, want 203.0.113.7", got)
	}
}

// TestServeDNS_UnknownTokenNoHit ensures a query for a token we never issued is
// still answered (valid reply) but recorded as nothing — we never log stray noise.
func TestServeDNS_UnknownTokenNoHit(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com", PublicHost: "203.0.113.7"})
	pkt := buildQuery(1, "deadbeef00.oob.example.com", dnsTypeA)
	resp, ok := c.handleDNSPacket(pkt, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)})
	if !ok {
		t.Fatal("valid query should still be answered")
	}
	if len(c.Hits()) != 0 {
		t.Fatalf("recorded a hit for an unknown token")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Errorf("ANCOUNT = %d, want 1 (PublicHost is an IPv4 literal)", binary.BigEndian.Uint16(resp[6:8]))
	}
}

// TestServeDNS_HostnamePublicHostNoAnswer verifies that when PublicHost is a name
// (not an IPv4 literal) we return a valid NODATA reply: header present, ANCOUNT=0.
func TestServeDNS_HostnamePublicHostNoAnswer(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com", PublicHost: "oob.example.com"})
	it := c.Register("blind-xss", "http://t/", "")
	pkt := buildQuery(7, it.Domain, dnsTypeA)
	resp, ok := c.handleDNSPacket(pkt, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)})
	if !ok {
		t.Fatal("query should be answered")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Errorf("ANCOUNT = %d, want 0 for hostname PublicHost", binary.BigEndian.Uint16(resp[6:8]))
	}
	// Hit still recorded — the lookup happened even if we have no A to give.
	if len(c.Poll(it.Token)) != 1 {
		t.Errorf("DNS hit should be recorded regardless of answerability")
	}
}

// TestServeDNS_GarbageNoPanic feeds a spread of malformed packets and asserts none
// panic and none are recorded as hits. Untrusted input must never crash the loop.
func TestServeDNS_GarbageNoPanic(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com", PublicHost: "203.0.113.7"})
	c.Register("ssrf", "http://t/", "") // a live token exists, but no garbage matches it

	cases := [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, 11),                        // one byte short of a header
		{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},    // header says 1 question, no body
		append(make([]byte, 12), 0xC0, 0x0C),    // QNAME starts with a compression pointer
		append(make([]byte, 12), 0x3f, 'a'),     // label length 63 but no bytes follow
		{0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0}, // QR=1 (a response, not a query)
	}
	for i, pkt := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			_, _ = c.handleDNSPacket(pkt, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9)})
		}()
	}
	if len(c.Hits()) != 0 {
		t.Fatalf("garbage produced %d hits, want 0", len(c.Hits()))
	}
}

// TestServeDNS_NonAQuery checks a non-A QTYPE (TXT) is recorded with the right
// Detail label and answered NODATA (we only synthesize A records).
func TestServeDNS_NonAQuery(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com", PublicHost: "203.0.113.7"})
	it := c.Register("sqli-oob", "http://t/", "id")
	const dnsTypeTXT = 16
	pkt := buildQuery(9, it.Domain, dnsTypeTXT)
	resp, ok := c.handleDNSPacket(pkt, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3)})
	if !ok {
		t.Fatal("TXT query should be answered")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Errorf("ANCOUNT = %d, want 0 for non-A query", binary.BigEndian.Uint16(resp[6:8]))
	}
	hits := c.Poll(it.Token)
	if len(hits) != 1 || hits[0].Detail != "TXT "+it.Domain {
		t.Fatalf("detail = %v, want %q", hits, "TXT "+it.Domain)
	}
}

// TestServeDNS_LiveSocket exercises the full serveDNS loop over a real UDP socket
// pair: Start the loop on a packet conn, send a hand-built query from a client
// socket, and assert both a recorded hit and a parseable A answer come back. This
// is the end-to-end proof that the read/parse/record/write path works on the wire.
func TestServeDNS_LiveSocket(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com", PublicHost: "203.0.113.7"})
	it := c.Register("cmd-injection", "http://t/", "")

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.serveDNS(ctx, server) }()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer client.Close()

	pkt := buildQuery(0xABCD, it.Domain, dnsTypeA)
	if _, err := client.WriteTo(pkt, server.LocalAddr()); err != nil {
		t.Fatalf("client write: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	rbuf := make([]byte, 512)
	n, _, err := client.ReadFrom(rbuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	resp := rbuf[:n]
	if binary.BigEndian.Uint16(resp[0:2]) != 0xABCD {
		t.Errorf("response ID not echoed over the wire")
	}
	q, _ := parseDNSQuery(pkt)
	got := parseFirstAnswer(t, resp, q)
	if got == nil || !got.Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("wire answer IP = %v, want 203.0.113.7", got)
	}

	// Give Record a beat to land, then confirm the hit. Poll a few times rather
	// than sleeping a fixed long interval.
	var hits []Hit
	for i := 0; i < 50; i++ {
		if hits = c.Poll(it.Token); len(hits) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(hits) != 1 || hits[0].Proto != ProtoDNS {
		t.Fatalf("got %v over the wire, want one ProtoDNS hit", hits)
	}

	// Cancelling ctx must stop the loop and close the conn.
	cancel()
}

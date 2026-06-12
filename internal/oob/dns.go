package oob

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// serveDNS runs a minimal, hand-rolled UDP DNS server until ctx is cancelled. It
// is the DNS half of the collaborator's listeners (the HTTP half is serveHTTP in
// collaborator.go). It exists because a blind payload often cannot reach back over
// HTTP — an egress-firewalled host still resolves names through a recursive
// resolver, so a bare DNS lookup of "<token>.oob.example.com" is the most reliable
// exfil signal we can catch.
//
// SECURITY: every byte read here is attacker-controlled and UNTRUSTED. We parse
// defensively, cap responses at the classic 512-byte UDP limit, and never panic on
// malformed input — a garbage packet is silently ignored, never logged as a hit.
// Only queries whose QNAME carries a token we actually issued are recorded.
func (c *Collaborator) serveDNS(ctx context.Context, conn net.PacketConn) error {
	// Close on cancellation so the blocking ReadFrom unblocks promptly. The read
	// deadline below is a backstop in case Close races a fresh deadline set.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 512)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Bounded read so a quiet socket still loops to re-check ctx.
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // deadline backstop — just re-loop
			}
			// Other errors (e.g. conn closed by Close) end the loop.
			return err
		}

		resp, ok := c.handleDNSPacket(buf[:n], src)
		if !ok {
			continue // malformed / nothing to answer — drop silently
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.WriteTo(resp, src)
	}
}

// dnsQuery is the decoded essentials of an inbound question we care about.
type dnsQuery struct {
	id       uint16
	qname    string // dotted, lowercase, no trailing dot
	qtype    uint16
	qclass   uint16
	question []byte // raw question section bytes (name+type+class), echoed verbatim
}

// DNS record/type constants we handle. Anything else gets an empty (NODATA) answer.
const (
	dnsTypeA  uint16 = 1
	dnsTypeIN uint16 = 1
)

// handleDNSPacket parses one query packet, records a Hit if its QNAME carries a
// known token, and builds the response bytes. ok=false means the packet was
// malformed or otherwise unanswerable and should be dropped without a reply.
//
// Splitting the parse+build out of the socket loop gives unit tests a pure seam:
// they can hand it raw bytes and inspect both the recorded Hit and the wire reply
// without standing up a real UDP socket.
func (c *Collaborator) handleDNSPacket(pkt []byte, src net.Addr) (resp []byte, ok bool) {
	q, ok := parseDNSQuery(pkt)
	if !ok {
		return nil, false
	}

	// Record only when the QNAME carries a token we issued. MatchToken splits on
	// dots, so "<token>.oob.example.com" resolves to its leading label.
	if tok, hit := c.MatchToken(q.qname); hit {
		qt := dnsTypeName(q.qtype)
		c.Record(Hit{
			Token:      tok,
			Proto:      ProtoDNS,
			RemoteAddr: addrString(src),
			Detail:     qt + " " + q.qname,
			At:         time.Now().UTC(),
		})
	}

	return buildDNSResponse(c.cfg, q), true
}

// parseDNSQuery decodes the header and the FIRST question of a standard query. It
// returns ok=false on any truncation or structural problem so callers can drop the
// packet. Only the first question is used (multi-question queries are vanishingly
// rare and not something we need to honour for a token catcher).
func parseDNSQuery(pkt []byte) (dnsQuery, bool) {
	var q dnsQuery
	if len(pkt) < 12 {
		return q, false // shorter than a DNS header
	}
	q.id = binary.BigEndian.Uint16(pkt[0:2])
	flags := binary.BigEndian.Uint16(pkt[2:4])
	qr := flags & 0x8000
	if qr != 0 {
		return q, false // this is a response, not a query — ignore
	}
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount < 1 {
		return q, false
	}

	// Walk the QNAME labels starting just past the 12-byte header.
	name, off, ok := readDNSName(pkt, 12)
	if !ok {
		return q, false
	}
	// QTYPE (2) + QCLASS (2) follow the name.
	if off+4 > len(pkt) {
		return q, false
	}
	q.qname = name
	q.qtype = binary.BigEndian.Uint16(pkt[off : off+2])
	q.qclass = binary.BigEndian.Uint16(pkt[off+2 : off+4])
	q.question = pkt[12 : off+4] // raw name+type+class, echoed verbatim
	return q, true
}

// readDNSName decodes a length-prefixed label sequence into a dotted, lowercase
// name and returns the offset just past the terminating zero byte. It rejects
// compression pointers (0xC0): a query's QNAME is never compressed, and refusing
// pointers means we can never follow an out-of-range or looping offset.
func readDNSName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	for {
		if off >= len(pkt) {
			return "", 0, false
		}
		l := int(pkt[off])
		if l == 0 {
			off++ // consume the root terminator
			break
		}
		if l&0xC0 != 0 {
			return "", 0, false // compression pointer or reserved bits — reject
		}
		off++
		if off+l > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, strings.ToLower(string(pkt[off:off+l])))
		off += l
		if len(labels) > 127 {
			return "", 0, false // absurd label count — bail
		}
	}
	return strings.Join(labels, "."), off, true
}

// buildDNSResponse builds a wire response for q. It echoes the question, copies the
// ID, and sets QR=1 with an authoritative-answer flag. For an A/IN query whose
// PublicHost parses as an IPv4 literal it returns one A record pointing there;
// otherwise (hostname or non-A query) it returns a valid header with ANCOUNT=0 — a
// well-formed NODATA reply rather than a lie about an address we don't know.
//
// The reply is capped implicitly: a single question + at most one A answer is far
// under 512 bytes, so no truncation handling is needed.
func buildDNSResponse(cfg Config, q dnsQuery) []byte {
	var ip4 net.IP
	if q.qtype == dnsTypeA && q.qclass == dnsTypeIN {
		if ip := net.ParseIP(cfg.PublicHost); ip != nil {
			ip4 = ip.To4() // non-nil only for genuine IPv4 literals
		}
	}

	ancount := uint16(0)
	if ip4 != nil {
		ancount = 1
	}

	out := make([]byte, 0, 512)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], q.id)
	// QR=1, Opcode=0 (standard), AA=1, RD/RA=0, RCODE=0 (NOERROR). 0x8400.
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT — we echo the one question
	binary.BigEndian.PutUint16(hdr[6:8], ancount)
	binary.BigEndian.PutUint16(hdr[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(hdr[10:12], 0) // ARCOUNT
	out = append(out, hdr[:]...)

	// Echo the question section verbatim.
	out = append(out, q.question...)

	if ip4 != nil {
		// Answer: NAME as a compression pointer to the question at offset 12
		// (0xC00C), TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4, RDATA=IPv4.
		var ans [12]byte
		binary.BigEndian.PutUint16(ans[0:2], 0xC00C) // pointer to offset 12
		binary.BigEndian.PutUint16(ans[2:4], dnsTypeA)
		binary.BigEndian.PutUint16(ans[4:6], dnsTypeIN)
		binary.BigEndian.PutUint32(ans[6:10], 60) // TTL
		binary.BigEndian.PutUint16(ans[10:12], 4) // RDLENGTH
		out = append(out, ans[:]...)
		out = append(out, ip4[0], ip4[1], ip4[2], ip4[3])
	}

	if len(out) > 512 {
		out = out[:512] // hard cap; never exercised by our single-answer replies
	}
	return out
}

// dnsTypeName renders a QTYPE as a short label for the Hit.Detail string. Unknown
// types fall back to "TYPE<n>" rather than guessing.
func dnsTypeName(t uint16) string {
	switch t {
	case dnsTypeA:
		return "A"
	case 28:
		return "AAAA"
	case 16:
		return "TXT"
	case 5:
		return "CNAME"
	case 2:
		return "NS"
	case 15:
		return "MX"
	case 255:
		return "ANY"
	default:
		var b [16]byte
		s := append(b[:0], "TYPE"...)
		s = appendUint(s, uint64(t))
		return string(s)
	}
}

// appendUint appends the decimal form of v without importing strconv into this
// hot, tiny helper. (strconv would be fine too; this keeps the file self-contained.)
func appendUint(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, tmp[i:]...)
}

// addrString renders a net.Addr as ip:port, mirroring how the HTTP side records
// RemoteAddr. A nil addr (only possible from a test seam) renders as "".
func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

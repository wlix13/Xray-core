package finalmask_test

import (
	"bytes"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	"golang.org/x/net/ipv4"
)

// oobConn is the subset of quic-go's OOBCapablePacketConn and batchConn that
// header masks over a *net.UDPConn must keep providing.
type oobConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

var testMasks = map[string]finalmask.Udpmask{
	"salamander": &salamander.Config{Password: "1234"},
	"aes128gcm":  &aes128gcm.Config{Password: "1234"},
}

func newOOBPair(t *testing.T, mask finalmask.Udpmask) (oobConn, oobConn, *net.UDPAddr) {
	t.Helper()
	mgr := finalmask.NewUdpmaskManager([]finalmask.Udpmask{mask})
	rawA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rawA.Close(); rawB.Close() })
	a, err := mgr.WrapPacketConnClient(rawA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mgr.WrapPacketConnServer(rawB)
	if err != nil {
		t.Fatal(err)
	}
	oa, ok := a.(oobConn)
	if !ok {
		t.Fatalf("header mask over *net.UDPConn lost out-of-band support: %T", a)
	}
	ob, ok := b.(oobConn)
	if !ok {
		t.Fatalf("header mask over *net.UDPConn lost out-of-band support: %T", b)
	}
	_ = rawA.SetDeadline(time.Now().Add(5 * time.Second))
	_ = rawB.SetDeadline(time.Now().Add(5 * time.Second))
	return oa, ob, rawB.LocalAddr().(*net.UDPAddr)
}

func newMessages(n int) []ipv4.Message {
	ms := make([]ipv4.Message, n)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 1500)}
		ms[i].OOB = make([]byte, 128)
	}
	return ms
}

// readBatchAll reads until want datagrams arrived and returns their payloads.
func readBatchAll(t *testing.T, c oobConn, want int) [][]byte {
	t.Helper()
	var got [][]byte
	for len(got) < want {
		ms := newMessages(8)
		n, err := c.ReadBatch(ms, 0)
		if err != nil {
			t.Fatalf("ReadBatch: %v (got %d of %d)", err, len(got), want)
		}
		for i := 0; i < n; i++ {
			if ms[i].N == 0 {
				t.Fatalf("datagram %d dropped by mask", len(got))
			}
			got = append(got, append([]byte(nil), ms[i].Buffers[0][:ms[i].N]...))
		}
	}
	return got
}

func TestHeaderMaskOOBSingle(t *testing.T) {
	for name, mask := range testMasks {
		t.Run(name, func(t *testing.T) { testHeaderMaskOOBSingle(t, mask) })
	}
}

func testHeaderMaskOOBSingle(t *testing.T, mask finalmask.Udpmask) {
	a, b, addrB := newOOBPair(t, mask)
	payload := bytes.Repeat([]byte{0x42}, 1200)

	// A datagram that does not unmask is skipped, not surfaced as empty.
	junk, err := net.DialUDP("udp", nil, addrB)
	if err != nil {
		t.Fatal(err)
	}
	defer junk.Close()
	if _, err := junk.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.WriteMsgUDP(payload, nil, addrB); err != nil {
		t.Fatal(err)
	}
	got := readBatchAll(t, b, 1)
	if !bytes.Equal(got[0], payload) {
		t.Fatalf("ReadBatch payload mismatch: %d bytes", len(got[0]))
	}

	if _, _, err := a.WriteMsgUDP(payload[:300], nil, addrB); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, _, _, _, err := b.ReadMsgUDP(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload[:300]) {
		t.Fatalf("ReadMsgUDP payload mismatch: %d bytes", n)
	}

	// The plain PacketConn path must keep working through the same conn.
	if _, err := b.WriteTo(payload[:100], a.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	n, _, err = a.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload[:100]) {
		t.Fatalf("ReadFrom payload mismatch: %d bytes", n)
	}
}

package finalmask

import (
	"context"
	"net"
	"slices"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type Udpmask interface {
	UDP()

	WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error)
	WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error)
}

type UdpmaskManager struct {
	udpmasks []Udpmask
}

func NewUdpmaskManager(udpmasks []Udpmask) *UdpmaskManager {
	return &UdpmaskManager{
		udpmasks: udpmasks,
	}
}

func (m *UdpmaskManager) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	var sizes []int
	var conns []net.PacketConn
	for i, mask := range slices.Backward(m.udpmasks) {
		if _, ok := mask.(headerConn); ok {
			conn, err := mask.WrapPacketConnClient(nil, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
			sizes = append(sizes, conn.(headerSize).Size())
			conns = append(conns, conn)
		} else {
			if len(conns) > 0 {
				raw = newHeaderManagerConn(raw, sizes, conns)
				sizes = nil
				conns = nil
			}
			var err error
			raw, err = mask.WrapPacketConnClient(raw, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(conns) > 0 {
		raw = newHeaderManagerConn(raw, sizes, conns)
		sizes = nil
		conns = nil
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	var sizes []int
	var conns []net.PacketConn
	for i, mask := range slices.Backward(m.udpmasks) {
		if _, ok := mask.(headerConn); ok {
			conn, err := mask.WrapPacketConnServer(nil, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
			sizes = append(sizes, conn.(headerSize).Size())
			conns = append(conns, conn)
		} else {
			if len(conns) > 0 {
				raw = newHeaderManagerConn(raw, sizes, conns)
				sizes = nil
				conns = nil
			}
			var err error
			raw, err = mask.WrapPacketConnServer(raw, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(conns) > 0 {
		raw = newHeaderManagerConn(raw, sizes, conns)
		sizes = nil
		conns = nil
	}
	return raw, nil
}

const (
	UDPSize = 4096
)

type headerConn interface {
	HeaderConn()
}

type headerSize interface {
	Size() int
}

type headerManagerConn struct {
	net.PacketConn

	sizes     []int
	conns     []net.PacketConn
	expansion int // bytes the masks add to a payload; at least headerSize()
}

// newHeaderManagerConn wraps raw with the header masks. Over a real UDP socket
// the wrapper stays out-of-band capable so that quic-go keeps its fast path.
func newHeaderManagerConn(raw net.PacketConn, sizes []int, conns []net.PacketConn) net.PacketConn {
	h := &headerManagerConn{PacketConn: raw, sizes: sizes, conns: conns}
	h.expansion = h.measureExpansion()
	if oob, ok := raw.(oobPacketConn); ok {
		return newOOBHeaderManagerConn(h, oob)
	}
	return h
}

func (c *headerManagerConn) headerSize() int {
	sum := 0
	for _, size := range c.sizes {
		sum += size
	}
	return sum
}

// measureExpansion masks a probe: an AEAD mask grows the payload by more than
// the header it declares.
func (c *headerManagerConn) measureExpansion() int {
	probe := make([]byte, 64)
	n, err := c.mask(probe, make([]byte, UDPSize))
	if err != nil {
		return c.headerSize()
	}
	return n - len(probe)
}

var (
	errMaskShort = errors.New("packet shorter than mask headers")
	errMaskLarge = errors.New("packet too large for mask")
	errMaskGSO   = errors.New("mask expansion varies between segments")
)

// unmask strips the mask layers from a received datagram in place and returns
// the payload, a sub-slice of b.
func (c *headerManagerConn) unmask(b []byte) ([]byte, error) {
	if len(b) < c.headerSize() {
		return nil, errMaskShort
	}
	for i := range c.conns {
		n, _, err := c.conns[i].ReadFrom(b)
		if err != nil {
			return nil, err
		}
		b = b[c.sizes[i] : n+c.sizes[i]]
	}
	return b, nil
}

// mask writes the masked form of p into out and returns its length.
func (c *headerManagerConn) mask(p []byte, out []byte) (int, error) {
	sum := c.headerSize()
	if c.expansion+len(p) > len(out) {
		return 0, errMaskLarge
	}
	n := copy(out[sum:], p)
	for i := len(c.conns) - 1; i >= 0; i-- {
		var err error
		n, err = c.conns[i].WriteTo(out[sum-c.sizes[i]:n+sum], nil)
		if err != nil {
			return 0, err
		}
		sum -= c.sizes[i]
	}
	return n, nil
}

func (c *headerManagerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b := p
	if len(b) < UDPSize {
		buf := buf.New()
		buf.Resize(0, UDPSize)
		b = buf.Bytes()
		defer buf.Release()
	}

	for {
		n, addr, err = c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		payload, uerr := c.unmask(b[:n])
		if uerr != nil {
			errors.LogErrorInner(context.Background(), uerr, "[mask] drop packet from ", addr, " with size ", n)
			continue
		}
		return copy(p, payload), addr, nil
	}
}

func (c *headerManagerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := buf.New()
	buf.Resize(0, UDPSize)
	b := buf.Bytes()
	defer buf.Release()

	n, err = c.mask(p, b)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}
	if _, err = c.PacketConn.WriteTo(b[:n], addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

type Tcpmask interface {
	TCP()

	WrapConnClient(net.Conn) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)
}

type TcpmaskManager struct {
	tcpmasks []Tcpmask
}

func NewTcpmaskManager(tcpmasks []Tcpmask) *TcpmaskManager {
	return &TcpmaskManager{
		tcpmasks: tcpmasks,
	}
}

func (m *TcpmaskManager) WrapConnClient(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range slices.Backward(m.tcpmasks) {
		raw, err = mask.WrapConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *TcpmaskManager) WrapConnServer(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range slices.Backward(m.tcpmasks) {
		raw, err = mask.WrapConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *TcpmaskManager) WrapListener(l net.Listener) (net.Listener, error) {
	return NewTcpListener(m, l)
}

type tcpListener struct {
	m *TcpmaskManager
	net.Listener
}

func NewTcpListener(m *TcpmaskManager, l net.Listener) (net.Listener, error) {
	return &tcpListener{
		m:        m,
		Listener: l,
	}, nil
}

func (l *tcpListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	newConn, err := l.m.WrapConnServer(conn)
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "mask err")
		_ = conn.Close()
		return nil, err
	}

	return newConn, nil
}

type TcpMaskConn interface {
	TcpMaskConn()
	RawConn() net.Conn
	Splice() bool
}

func UnwrapTcpMask(conn net.Conn) net.Conn {
	for {
		if v, ok := conn.(TcpMaskConn); ok {
			if !v.Splice() {
				return conn
			}
			conn = v.RawConn()
		} else {
			return conn
		}
	}
}

package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"golang.zx2c4.com/wireguard/conn"
)

// socketBufferSize is what wireguard-go requests too; the kernel clamps it.
const socketBufferSize = 7 << 20

func tuneUDPConn(c net.PacketConn) {
	if uc, ok := c.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(socketBufferSize)
		_ = uc.SetWriteBuffer(socketBufferSize)
	}
}

type bind struct {
	resolveFunc func(host string) (net.IP, error)
	listenFunc  func() (net.PacketConn, error)
	downFunc    func() error
	reserved    []byte

	// readCounter and writeCounter account bytes received from / sent to peers.
	readCounter  stats.Counter
	writeCounter stats.Counter

	net.PacketConn
	batch   *batchConn // non-nil when the socket supports batched I/O
	closeCh chan struct{}
	mu      sync.Mutex
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.PacketConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c, err := b.listenFunc()
	if err != nil {
		return nil, 0, err
	}
	b.PacketConn = c
	b.batch = newBatchConn(c)
	ch := make(chan struct{})
	b.closeCh = ch

	readOne := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := c.ReadFrom(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: addr.(*net.UDPAddr).AddrPort()}
		return 1, nil
	}
	read := readOne
	if b.batch != nil {
		read = b.batch.read
	}

	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		for {
			n, err := read(bufs, sizes, eps)
			if err != nil {
				if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
					select {
					case <-ch:
					default:
						errors.LogErrorInner(context.Background(), err, "unexpected closed")
						b.mu.Lock()
						down := b.downFunc
						b.mu.Unlock()
						if down != nil {
							go func() {
								common.Must(down())
							}()
						}
					}
					return 0, net.ErrClosed
				}
				errors.LogErrorInner(context.Background(), err, "bind recv err")
				continue
			}
			b.received(bufs, sizes, n)
			return n, nil
		}
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// received clears the reserved bytes of n received packets and accounts them.
func (b *bind) received(bufs [][]byte, sizes []int, n int) {
	var total int64
	for i := 0; i < n; i++ {
		if sizes[i] > 3 {
			bufs[i][1] = 0
			bufs[i][2] = 0
			bufs[i][3] = 0
		}
		total += int64(sizes[i])
	}
	if b.readCounter != nil && total > 0 {
		b.readCounter.Add(total)
	}
}

// setDownFunc is called once the device exists, which may already be opening
// the bind from its TUN event reader.
func (b *bind) setDownFunc(f func() error) {
	b.mu.Lock()
	b.downFunc = f
	b.mu.Unlock()
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.PacketConn != nil {
		close(b.closeCh)
		_ = b.PacketConn.Close()
		b.PacketConn = nil
		b.batch = nil
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) (err error) {
	b.mu.Lock()
	c := b.PacketConn
	bc := b.batch
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	for i := range bufs {
		if len(bufs[i]) > 3 && len(b.reserved) == 3 {
			bufs[i][1] = b.reserved[0]
			bufs[i][2] = b.reserved[1]
			bufs[i][3] = b.reserved[2]
		}
	}
	addr := net.UDPAddrFromAddrPort(ep.(*conn.StdNetEndpoint).AddrPort)
	var sent int64
	if bc != nil {
		var n int
		n, err = bc.write(bufs, addr)
		for _, buf := range bufs[:n] {
			sent += int64(len(buf))
		}
	} else {
		for i := range bufs {
			var n int
			if n, err = c.WriteTo(bufs[i], addr); err != nil {
				break
			}
			if n > 0 {
				sent += int64(len(bufs[i]))
			}
		}
	}
	if b.writeCounter != nil && sent > 0 {
		b.writeCounter.Add(sent)
	}
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "bind send err")
		return err
	}
	return nil
}

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.resolveFunc == nil {
		e, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		return &conn.StdNetEndpoint{
			AddrPort: e,
		}, nil
	}
	host, sport, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port " + sport)
	}
	ip, err := b.resolveFunc(host)
	if err != nil {
		return nil, err
	}
	addr, _ := netip.AddrFromSlice(ip)
	return &conn.StdNetEndpoint{
		AddrPort: netip.AddrPortFrom(addr, uint16(port)),
	}, nil
}

// BatchSize is how many packets wireguard-go may pass to Send or expect from
// a ReceiveFunc at once.
func (b *bind) BatchSize() int {
	return bindBatchSize
}

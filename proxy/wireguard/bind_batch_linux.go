//go:build linux

package wireguard

import (
	"io"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

const bindBatchSize = conn.IdealBatchSize

// batchPacketConn is satisfied by both ipv4.PacketConn and ipv6.PacketConn
// (their Message types are the same alias).
type batchPacketConn interface {
	ReadBatch(ms []ipv6.Message, flags int) (int, error)
	WriteBatch(ms []ipv6.Message, flags int) (int, error)
}

// batchConn moves datagrams with recvmmsg/sendmmsg.
type batchConn struct {
	pc     batchPacketConn
	rxMsgs []ipv6.Message // only the single receive goroutine uses these
	txPool sync.Pool      // *[]ipv6.Message; Send runs concurrently, one goroutine per peer
}

// newBatchConn returns nil when c is not a plain UDP socket (e.g. wrapped by a
// UDP mask); the bind then falls back to per-packet ReadFrom/WriteTo.
func newBatchConn(c net.PacketConn) *batchConn {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return nil
	}
	bc := &batchConn{rxMsgs: newMessages(bindBatchSize)}
	bc.txPool.New = func() any {
		msgs := newMessages(bindBatchSize)
		return &msgs
	}
	if la, ok := uc.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		bc.pc = ipv4.NewPacketConn(uc)
	} else {
		bc.pc = ipv6.NewPacketConn(uc)
	}
	return bc
}

func newMessages(n int) []ipv6.Message {
	msgs := make([]ipv6.Message, n)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}
	return msgs
}

// read receives up to len(bufs) datagrams in one recvmmsg call; the socket is
// non-blocking under the Go runtime, so it returns as soon as one is available.
func (bc *batchConn) read(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	msgs := bc.rxMsgs
	if len(bufs) < len(msgs) {
		msgs = msgs[:len(bufs)]
	}
	for i := range msgs {
		msgs[i].Buffers[0] = bufs[i]
		msgs[i].N = 0
		msgs[i].Addr = nil
	}
	n, err := bc.pc.ReadBatch(msgs, 0)
	if err != nil {
		return 0, err
	}
	for i := 0; i < n; i++ {
		sizes[i] = msgs[i].N
		eps[i] = &conn.StdNetEndpoint{AddrPort: msgs[i].Addr.(*net.UDPAddr).AddrPort()}
	}
	return n, nil
}

// write sends bufs to addr with as few sendmmsg calls as possible and returns
// how many were sent.
func (bc *batchConn) write(bufs [][]byte, addr *net.UDPAddr) (int, error) {
	msgsp := bc.txPool.Get().(*[]ipv6.Message)
	defer bc.txPool.Put(msgsp)
	msgs := *msgsp
	for start := 0; start < len(bufs); {
		end := start + len(msgs)
		if end > len(bufs) {
			end = len(bufs)
		}
		for i := start; i < end; i++ {
			msgs[i-start].Buffers[0] = bufs[i]
			msgs[i-start].Addr = addr
		}
		n, err := bc.pc.WriteBatch(msgs[:end-start], 0)
		if err != nil {
			return start, err
		}
		if n == 0 {
			return start, io.ErrShortWrite
		}
		start += n
	}
	return len(bufs), nil
}

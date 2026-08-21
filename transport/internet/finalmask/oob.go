package finalmask

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// oobPacketConn is what quic-go needs from a UDP socket to use its fast path
// (quic.OOBCapablePacketConn); *net.UDPConn satisfies it.
type oobPacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

type batchReader interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

// maxDatagramSize bounds a masked datagram, including a GSO batch of them.
const maxDatagramSize = 65535

// oobHeaderManagerConn is a headerManagerConn over a real UDP socket that also
// satisfies quic-go's OOBCapablePacketConn and batchConn interfaces, so that
// quic-go keeps ECN, DF, socket buffer sizing, batched reads and GSO through
// header masks. ReadBatch has to be provided here: quic-go would otherwise let
// x/net read the raw file descriptor and bypass the masks.
type oobHeaderManagerConn struct {
	*headerManagerConn
	raw   oobPacketConn
	batch batchReader

	readMu   sync.Mutex
	readMsgs []ipv4.Message // scratch messages with our own data buffers
	bufPool  sync.Pool      // *[]byte of maxDatagramSize
	drops    atomic.Uint64
}

const dropLogInterval = 1024

func (c *oobHeaderManagerConn) dropped(err error, addr net.Addr, size int) {
	if n := c.drops.Add(1); n%dropLogInterval == 1 {
		errors.LogDebugInner(context.Background(), err, "[mask] dropped ", n, " packets, last from ", addr, " with size ", size)
	}
}

func newOOBHeaderManagerConn(h *headerManagerConn, raw oobPacketConn) *oobHeaderManagerConn {
	c := &oobHeaderManagerConn{headerManagerConn: h, raw: raw}
	if la, ok := raw.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		c.batch = ipv4.NewPacketConn(raw)
	} else {
		c.batch = ipv6.NewPacketConn(raw)
	}
	c.bufPool.New = func() any {
		b := make([]byte, maxDatagramSize)
		return &b
	}
	return c
}

func (c *oobHeaderManagerConn) SyscallConn() (syscall.RawConn, error) {
	return c.raw.SyscallConn()
}

func (c *oobHeaderManagerConn) SetReadBuffer(n int) error {
	return c.raw.SetReadBuffer(n)
}

func (c *oobHeaderManagerConn) SetWriteBuffer(n int) error {
	return c.raw.SetWriteBuffer(n)
}

// ReadBatch reads datagrams into scratch buffers and unmasks them into the
// caller's messages, skipping those that do not unmask.
func (c *oobHeaderManagerConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readMsgs) < len(ms) {
		c.readMsgs = append(c.readMsgs, ipv4.Message{Buffers: [][]byte{make([]byte, UDPSize)}})
	}
	scratch := c.readMsgs[:len(ms)]
	for i := range scratch {
		scratch[i].Buffers[0] = scratch[i].Buffers[0][:UDPSize]
		scratch[i].OOB = ms[i].OOB // out-of-band data lands in the caller's buffer
		scratch[i].Addr = nil
		scratch[i].N, scratch[i].NN, scratch[i].Flags = 0, 0, 0
	}
	n, err := c.batch.ReadBatch(scratch, flags)
	out := 0
	for i := 0; i < n; i++ {
		payload, uerr := c.unmask(scratch[i].Buffers[0][:scratch[i].N])
		if uerr != nil || len(payload) > len(ms[out].Buffers[0]) {
			c.dropped(uerr, scratch[i].Addr, scratch[i].N)
			continue
		}
		if out != i {
			copy(ms[out].OOB, ms[i].OOB[:scratch[i].NN])
		}
		ms[out].Addr, ms[out].NN, ms[out].Flags = scratch[i].Addr, scratch[i].NN, scratch[i].Flags
		ms[out].N = copy(ms[out].Buffers[0], payload)
		out++
	}
	return out, err
}

func (c *oobHeaderManagerConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	bp := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bp)
	scratch := (*bp)[:UDPSize]
	for {
		n, oobn, flags, addr, err = c.raw.ReadMsgUDP(scratch, oob)
		if err != nil {
			return 0, oobn, flags, addr, err
		}
		payload, uerr := c.unmask(scratch[:n])
		if uerr != nil {
			c.dropped(uerr, addr, n)
			continue
		}
		return copy(b, payload), oobn, flags, addr, nil
	}
}

// WriteMsgUDP masks b, or with a UDP_SEGMENT control message every segment of
// b, and passes the out-of-band data through with the segment size adjusted
// for the mask expansion.
func (c *oobHeaderManagerConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	bp := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bp)
	out := *bp

	segSize := gsoSegmentSize(oob)
	if segSize <= 0 {
		m, merr := c.mask(b, out)
		if merr != nil {
			return 0, 0, merr
		}
		if _, _, err := c.raw.WriteMsgUDP(out[:m], oob, addr); err != nil {
			return 0, 0, err
		}
		return len(b), len(oob), nil
	}

	// GSO requires all segments but the last to have the segment size, so
	// every masked segment must grow by the same amount. A single datagram
	// gets a segment size covering all of it, and a batch that would exceed
	// the maximum datagram size after masking is sent in several.
	var oobBuf [256]byte
	oobSeg := oobBuf[:]
	if len(oob) > len(oobSeg) {
		oobSeg = make([]byte, len(oob))
	}
	oobSeg = oobSeg[:copy(oobSeg, oob)]
	segSize = min(segSize, len(b))
	segMasked := segSize + c.expansion
	setGSOSegmentSize(oobSeg, segMasked)

	pos := 0
	flush := func() error {
		if pos == 0 {
			return nil
		}
		_, _, werr := c.raw.WriteMsgUDP(out[:pos], oobSeg, addr)
		pos = 0
		return werr
	}
	for start := 0; start < len(b); start += segSize {
		end := min(start+segSize, len(b))
		if pos+segMasked > len(out) {
			if err := flush(); err != nil {
				return 0, 0, err
			}
		}
		m, merr := c.mask(b[start:end], out[pos:])
		if merr != nil {
			return 0, 0, merr
		}
		if m != end-start+c.expansion {
			return 0, 0, errMaskGSO
		}
		pos += m
	}
	if err := flush(); err != nil {
		return 0, 0, err
	}
	return len(b), len(oob), nil
}

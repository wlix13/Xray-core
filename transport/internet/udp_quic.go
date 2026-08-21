package internet

import "net"

// quicSocketBufferSize is what quic-go requests for its sockets.
const quicSocketBufferSize = 8 << 20

// TuneUDPConnForQUIC applies to a UDP socket what quic-go would do itself if
// it were handed the socket directly: large send/receive buffers and the DF
// bit, without which its path MTU discovery probes are fragmented instead of
// dropped. Use it on sockets that are wrapped (UDP masks, UDP hop) before
// quic-go sees them.
func TuneUDPConnForQUIC(pc net.PacketConn) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	_ = uc.SetReadBuffer(quicSocketBufferSize)
	_ = uc.SetWriteBuffer(quicSocketBufferSize)
	if rc, err := uc.SyscallConn(); err == nil {
		_ = rc.Control(setDontFragment)
	}
}

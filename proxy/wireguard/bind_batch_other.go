//go:build !linux

package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/conn"
)

// Only Linux has recvmmsg/sendmmsg; elsewhere the bind moves one packet per syscall.
const bindBatchSize = 1

type batchConn struct{}

func newBatchConn(net.PacketConn) *batchConn {
	return nil
}

func (*batchConn) read([][]byte, []int, []conn.Endpoint) (int, error) {
	panic("batched bind I/O is only available on linux")
}

func (*batchConn) write([][]byte, *net.UDPAddr) (int, error) {
	panic("batched bind I/O is only available on linux")
}

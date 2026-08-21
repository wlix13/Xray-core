//go:build linux

package finalmask

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

// udpSegmentData returns the payload of the UDP_SEGMENT control message in
// oob (a uint16 segment size, as quic-go writes it), or nil.
func udpSegmentData(oob []byte) []byte {
	for off := 0; off+unix.SizeofCmsghdr <= len(oob); {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[off]))
		if int(h.Len) < unix.SizeofCmsghdr || off+int(h.Len) > len(oob) {
			return nil
		}
		if h.Level == unix.IPPROTO_UDP && h.Type == unix.UDP_SEGMENT {
			data := oob[off+unix.CmsgLen(0) : off+int(h.Len)]
			if len(data) < 2 {
				return nil
			}
			return data[:2]
		}
		off += unix.CmsgSpace(int(h.Len) - unix.CmsgLen(0))
	}
	return nil
}

func gsoSegmentSize(oob []byte) int {
	if data := udpSegmentData(oob); data != nil {
		return int(binary.NativeEndian.Uint16(data))
	}
	return 0
}

func setGSOSegmentSize(oob []byte, size int) {
	if data := udpSegmentData(oob); data != nil {
		binary.NativeEndian.PutUint16(data, uint16(size))
	}
}

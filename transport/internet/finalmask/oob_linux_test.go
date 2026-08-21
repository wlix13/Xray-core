//go:build linux

package finalmask_test

import (
	"bytes"
	"syscall"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/sys/unix"
)

// appendUDPSegmentSizeMsg builds the UDP_SEGMENT control message the way
// quic-go does.
func appendUDPSegmentSizeMsg(b []byte, size uint16) []byte {
	startLen := len(b)
	const dataLen = 2
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(dataLen))
	*(*uint16)(unsafe.Pointer(&b[startLen+unix.CmsgSpace(0)])) = size
	return b
}

// TestHeaderMaskOOBGSO sends GSO batches through the mask and expects every
// segment to arrive as its own, correctly unmasked datagram.
func TestHeaderMaskOOBGSO(t *testing.T) {
	for name, mask := range testMasks {
		t.Run(name, func(t *testing.T) { testHeaderMaskOOBGSO(t, mask) })
	}
}

func testHeaderMaskOOBGSO(t *testing.T, mask finalmask.Udpmask) {
	a, b, addrB := newOOBPair(t, mask)
	const segSize = 500
	payload := make([]byte, 3*segSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	oob := appendUDPSegmentSizeMsg(nil, segSize)
	for _, size := range []int{3*segSize - 200, 3 * segSize, segSize - 1} {
		if _, _, err := a.WriteMsgUDP(payload[:size], oob, addrB); err != nil {
			t.Skipf("UDP GSO not available here: %v", err)
		}
		want := (size + segSize - 1) / segSize
		got := readBatchAll(t, b, want)
		for i := 0; i < want; i++ {
			seg := payload[i*segSize : min((i+1)*segSize, size)]
			if !bytes.Equal(got[i], seg) {
				t.Fatalf("size %d segment %d mismatch: got %d bytes, want %d", size, i, len(got[i]), len(seg))
			}
		}
	}
}

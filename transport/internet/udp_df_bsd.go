//go:build darwin || freebsd

package internet

import "golang.org/x/sys/unix"

func setDontFragment(fd uintptr) {
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
}

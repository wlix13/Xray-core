//go:build windows

package internet

import "syscall"

const (
	ipDontFragment = 14 // IP_DONTFRAGMENT
	ipv6DontFrag   = 14 // IPV6_DONTFRAG
)

func setDontFragment(fd uintptr) {
	_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipDontFragment, 1)
	_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, 1)
}

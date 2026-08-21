//go:build !linux && !darwin && !freebsd && !windows

package internet

func setDontFragment(uintptr) {}

//go:build !linux

package finalmask

// UDP GSO only exists on Linux.
func gsoSegmentSize([]byte) int { return 0 }

func setGSOSegmentSize([]byte, int) {}

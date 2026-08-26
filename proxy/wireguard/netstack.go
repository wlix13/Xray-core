/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// outboundQueueSize bounds the packets queued for the TUN reader; further ones
// are dropped like on a full NIC TX ring. GSO lets the TCP sender burst a
// window at once, so it is deeper than wireguard-go's 1024.
const outboundQueueSize = 8192

type netTun struct {
	ep           *linkEndpoint
	stack        *stack.Stack
	events       chan tun.Event
	mtu          int
	dnsServers   []netip.Addr
	hasV4, hasV6 bool
}

// linkEndpoint queues stack-originated packets for netTun.Read without
// blocking the stack and injects peer packets straight into the dispatcher.
type linkEndpoint struct {
	mtu      uint32
	outbound chan *stack.PacketBuffer

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	closed     bool
}

var (
	_ stack.LinkEndpoint = (*linkEndpoint)(nil)
	_ stack.GSOEndpoint  = (*linkEndpoint)(nil)
)

func newLinkEndpoint(mtu uint32) *linkEndpoint {
	return &linkEndpoint{
		mtu:      mtu,
		outbound: make(chan *stack.PacketBuffer, outboundQueueSize),
	}
}

func (e *linkEndpoint) MTU() uint32 {
	return e.mtu
}

func (e *linkEndpoint) SetMTU(mtu uint32) {
	e.mtu = mtu
}

func (e *linkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *linkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *linkEndpoint) SetLinkAddress(tcpip.LinkAddress) {}

// Everything that reaches the stack has passed WireGuard's AEAD, so inbound
// checksums need no verification (kernel WireGuard sets CHECKSUM_UNNECESSARY).
func (e *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

// The TCP sender builds one segment per write and the stack splits it into
// MTU-sized packets before they reach WritePackets.
func (e *linkEndpoint) GSOMaxSize() uint32 {
	return stack.GVisorGSOMaxSize
}

func (e *linkEndpoint) SupportedGSO() stack.SupportedGSO {
	return stack.GVisorGSOSupported
}

func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
}

func (e *linkEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *linkEndpoint) Wait() {}

func (e *linkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *linkEndpoint) AddHeader(*stack.PacketBuffer) {}

func (e *linkEndpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

func (e *linkEndpoint) SetOnCloseAction(func()) {}

// Close is idempotent: the stack calls it on RemoveNIC and netTun.Close too.
func (e *linkEndpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	e.dispatcher = nil
	close(e.outbound)
	for pkt := range e.outbound {
		pkt.DecRef()
	}
}

// WritePackets queues for netTun.Read; when the queue is full the rest are
// dropped without blocking, as channel.Endpoint does.
func (e *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return 0, &tcpip.ErrClosedForSend{}
	}
	n := 0
	for _, pkt := range pkts.AsSlice() {
		pkt.IncRef()
		select {
		case e.outbound <- pkt:
			n++
		default:
			pkt.DecRef()
			return n, nil
		}
	}
	return n, nil
}

// inject delivers a packet received from the WireGuard peer to the stack.
func (e *linkEndpoint) inject(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	dispatcher := e.dispatcher
	e.mu.RUnlock()
	if dispatcher != nil {
		dispatcher.DeliverNetworkPacket(proto, pkt)
	}
}

// copyPacket copies the whole packet (headers and payload) into dst and
// returns the number of bytes copied, or 0 if it does not fit.
func copyPacket(pkt *stack.PacketBuffer, dst []byte) int {
	if pkt.Size() > len(dst) {
		return 0
	}
	views, offset := pkt.AsViewList()
	n := 0
	for v := views.Front(); v != nil; v = v.Next() {
		s := v.AsSlice()
		if offset > 0 {
			if offset >= len(s) {
				offset -= len(s)
				continue
			}
			s = s[offset:]
			offset = 0
		}
		n += copy(dst[n:], s)
	}
	return n
}

func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu int, handleLocal bool) (tun.Device, *Net, *stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        handleLocal,
	}
	dev := &netTun{
		ep:         newLinkEndpoint(uint32(mtu)),
		stack:      stack.New(opts),
		events:     make(chan tun.Event, 10),
		dnsServers: dnsServers,
		mtu:        mtu,
	}
	if err := configureTCP(dev.stack); err != nil {
		return nil, nil, nil, err
	}
	tcpipErr := dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	tnet := &Net{
		DialContextTCPAddrPort: dev.DialContextTCPAddrPort,
		DialUDPAddrPort:        dev.DialUDPAddrPort,
		dnsServers:             dev.dnsServers,
		hasV4:                  dev.hasV4,
		hasV6:                  dev.hasV6,
	}

	dev.events <- tun.EventUp
	return dev, tnet, dev.stack, nil
}

const (
	tcpRecvBufMin     = tcp.MinBufferSize
	tcpRecvBufDefault = tcp.DefaultReceiveBufferSize // auto-tuned up to tcpRecvBufMax
	tcpRecvBufMax     = 8 << 20
	tcpSendBufMin     = tcp.MinBufferSize
	tcpSendBufDefault = 4 << 20 // not auto-tuned; bounds the fillable BDP
	tcpSendBufMax     = 8 << 20
)

// configureTCP mirrors proxy/tun/stack_gvisor.go: cubic, SACK, receive buffer
// auto-tuning up to 8 MiB, a larger send buffer, RACK/TLP off (#5600).
func configureTCP(s *stack.Stack) error {
	cc := tcpip.CongestionControlOption("cubic")
	sack := tcpip.TCPSACKEnabled(true)
	moderateRecvBuf := tcpip.TCPModerateReceiveBufferOption(true)
	recovery := tcpip.TCPRecovery(0)
	recvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcpRecvBufMin,
		Default: tcpRecvBufDefault,
		Max:     tcpRecvBufMax,
	}
	sendBuf := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcpSendBufMin,
		Default: tcpSendBufDefault,
		Max:     tcpSendBufMax,
	}
	for _, opt := range []tcpip.SettableTransportProtocolOption{&cc, &sack, &moderateRecvBuf, &recovery, &recvBuf, &sendBuf} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return fmt.Errorf("could not set TCP option %T: %v", opt, err)
		}
	}
	return nil
}

func (tun *netTun) Name() (string, error) {
	return "go", nil
}

func (tun *netTun) File() *os.File {
	return nil
}

func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

// Read blocks for one packet, then drains what else is queued, up to len(bufs).
func (tun *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-tun.ep.outbound
	if !ok {
		return 0, os.ErrClosed
	}
	n := 0
	for {
		sizes[n] = copyPacket(pkt, bufs[n][offset:])
		pkt.DecRef()
		n++
		if n == len(bufs) {
			return n, nil
		}
		select {
		case pkt, ok = <-tun.ep.outbound:
			if !ok {
				return n, nil
			}
		default:
			return n, nil
		}
	}
}

// Write injects packets received from the WireGuard peer into the stack.
func (tun *netTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch packet[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		tun.ep.inject(proto, pkb)
		pkb.DecRef()
	}
	return len(bufs), nil
}

func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1) // also closes the link endpoint
	tun.stack.Close()
	tun.ep.Close()

	if tun.events != nil {
		close(tun.events)
	}

	return nil
}

func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

// BatchSize lets wireguard-go process up to conn.IdealBatchSize packets at once.
func (tun *netTun) BatchSize() int {
	return conn.IdealBatchSize
}

func (tun *netTun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, tun.stack, fa, pn)
}

func (tun *netTun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	var pn tcpip.NetworkProtocolNumber = ipv6.ProtocolNumber
	if raddr.IsValid() || raddr.Port() > 0 {
		_, pn = convertToFullAddr(raddr)
	}
	conn, err := gonet.DialUDP(tun.stack, nil, nil, pn)
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{
		PacketConn: conn,
		Dest:       net.UDPAddrFromAddrPort(raddr),
	}, nil
}

type Net struct {
	DialContextTCPAddrPort func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	DialUDPAddrPort        func(laddr, raddr netip.AddrPort) (net.Conn, error)
	dnsServers             []netip.Addr
	hasV4, hasV6           bool
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

var (
	errNoSuchHost                   = errors.New("no such host")
	errLameReferral                 = errors.New("lame referral")
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")
	errServerMisbehaving            = errors.New("server misbehaving")
	errInvalidDNSResponse           = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")
	errCanceled                     = errors.New("operation was canceled")
	errTimeout                      = errors.New("i/o timeout")
)

func (net *Net) LookupHost(host string) (addrs []net.IP, ttl uint32, err error) {
	return net.LookupContextHost(context.Background(), host)
}

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}

func randU16() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b[:])
}

func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = randU16()
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, err
}

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 1280)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

func (tnet *Net) exchange(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}

	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		var c net.Conn
		var err error
		if useUDP {
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
		} else {
			c, err = tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server, 53))
		}

		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if useUDP {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		if h.Truncated {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}
	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}
	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func (tnet *Net) tryOneName(ctx context.Context, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error

	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	for i := 0; i < 2; i++ {
		for _, server := range tnet.dnsServers {
			p, h, err := tnet.exchange(ctx, server, q, time.Second*5)
			if err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					dnsErr.IsTimeout = true
				}
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if err == errServerTemporarilyMisbehaving {
					dnsErr.IsTemporary = true
				}
				if err == errNoSuchHost {
					dnsErr.IsNotFound = true
					return p, server.String(), dnsErr
				}
				lastErr = dnsErr
				continue
			}

			err = skipToAnswer(&p, qtype)
			if err == nil {
				return p, server.String(), nil
			}
			lastErr = &net.DNSError{
				Err:    err.Error(),
				Name:   name,
				Server: server.String(),
			}
			if err == errNoSuchHost {
				lastErr.(*net.DNSError).IsNotFound = true
				return p, server.String(), lastErr
			}
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]net.IP, uint32, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, 0, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []net.IP{ip.AsSlice()}, 0, nil
	}

	if !isDomainName(host) {
		return nil, 0, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}
	var addrsV4, addrsV6 []netip.Addr
	lanes := 0
	if tnet.hasV4 {
		lanes++
	}
	if tnet.hasV6 {
		lanes++
	}
	lane := make(chan result, lanes)
	var lastErr error
	if tnet.hasV4 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeA)
			lane <- result{p, server, err}
		}()
	}
	if tnet.hasV6 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)
			lane <- result{p, server, err}
		}()
	}
	ttl := uint32(300)
	for l := 0; l < lanes; l++ {
		result := <-lane
		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}

	loop:
		for {
			h, err := result.p.AnswerHeader()
			if err != nil && err != dnsmessage.ErrSectionDone {
				lastErr = &net.DNSError{
					Err:    errCannotMarshalDNSMessage.Error(),
					Name:   host,
					Server: result.server,
				}
			}
			if err != nil {
				break
			}
			switch h.Type {
			case dnsmessage.TypeA:
				a, err := result.p.AResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				ttl = min(ttl, h.TTL)
				addrsV4 = append(addrsV4, netip.AddrFrom4(a.A))

			case dnsmessage.TypeAAAA:
				aaaa, err := result.p.AAAAResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				ttl = min(ttl, h.TTL)
				addrsV6 = append(addrsV6, netip.AddrFrom16(aaaa.AAAA))

			default:
				if err := result.p.SkipAnswer(); err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				continue
			}
		}
	}
	// We don't do RFC6724. Instead just put V6 addresses first if an IPv6 address is enabled
	var addrs []netip.Addr
	if tnet.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}

	if len(addrs) == 0 && lastErr != nil {
		return nil, 0, lastErr
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		ips = append(ips, ip.AsSlice())
	}
	return ips, ttl, nil
}

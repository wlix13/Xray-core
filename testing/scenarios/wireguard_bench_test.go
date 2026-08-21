package scenarios

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"golang.org/x/sync/errgroup"
)

const wgBenchBytes = 64 << 20

// wgBenchSetup starts client (dokodemo -> WireGuard outbound) and server
// (WireGuard inbound -> freedom redirected to sinkDest) instances in-process
// and returns the dokodemo port plus a closer.
func wgBenchSetup(sinkDest xnet.Destination) (xnet.Port, func()) {
	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	serverPublic, _ := conf.ParseWireGuardKey("MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")
	clientPublic, _ := conf.ParseWireGuardKey("osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=")

	fakeDest := xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 80)

	serverPort := udp.PickPort()
	quietLog := serial.ToTypedMessage(&log.Config{
		ErrorLogLevel: clog.Severity_Error,
		ErrorLogType:  log.LogType_Console,
	})

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{quietLog},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(serverPort)}},
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				Endpoint:  []string{"10.0.0.1"},
				Mtu:       1420,
				SecretKey: serverPrivate,
				Users: []*protocol.User{{
					Email: "wg@example.com",
					Account: serial.ToTypedMessage(&wireguard.PeerConfig{
						PublicKey:  clientPublic,
						AllowedIps: []string{"10.0.0.2/32"},
					}),
				}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(sinkDest.Address),
						Port:    uint32(sinkDest.Port),
					},
				},
			}),
		}},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{quietLog},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(clientPort)}},
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  xnet.NewIPOrDomain(fakeDest.Address),
				RewritePort:     uint32(fakeDest.Port),
				AllowedNetworks: []xnet.Network{xnet.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				IsClient:    true,
				NoKernelTun: true,
				Endpoint:    []string{"10.0.0.2"},
				Mtu:         1420,
				SecretKey:   clientPrivate,
				Peers: []*wireguard.PeerConfig{{
					Endpoint:   "127.0.0.1:" + serverPort.String(),
					PublicKey:  serverPublic,
					AllowedIps: []string{"0.0.0.0/0", "::0/0"},
				}},
			}),
		}},
	}

	serverInst, err := core.New(withDefaultApps(serverConfig))
	common.Must(err)
	common.Must(serverInst.Start())
	clientInst, err := core.New(withDefaultApps(clientConfig))
	common.Must(err)
	common.Must(clientInst.Start())
	return clientPort, func() {
		clientInst.Close()
		serverInst.Close()
	}
}

func listenTCP() (net.Listener, xnet.Destination) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	return l, xnet.DestinationFromAddr(l.Addr())
}

// BenchmarkWireguardDownload streams wgBenchBytes from the sink server to the
// client through the tunnel (server -> WG inbound is the TCP sender).
func serveDownloads(l net.Listener) {
	buf := make([]byte, 64<<10)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			remain := wgBenchBytes
			for remain > 0 {
				n := len(buf)
				if remain < n {
					n = remain
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
				remain -= n
			}
		}()
	}
}

func BenchmarkWireguardDownload(b *testing.B) {
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := wgBenchSetup(dest)
	defer closer()

	b.SetBytes(wgBenchBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+port.String())
		common.Must(err)
		n, err := io.Copy(io.Discard, c)
		c.Close()
		if err != nil || n != wgBenchBytes {
			b.Fatalf("download: n=%d err=%v", n, err)
		}
	}
}

// BenchmarkWireguardDownloadParallel downloads over several connections at
// once, which shows whether a single stream is bound by latency or by CPU.
func BenchmarkWireguardDownloadParallel(b *testing.B) {
	const streams = 4
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := wgBenchSetup(dest)
	defer closer()

	b.SetBytes(streams * wgBenchBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var errg errgroup.Group
		for s := 0; s < streams; s++ {
			errg.Go(func() error {
				c, err := net.Dial("tcp", "127.0.0.1:"+port.String())
				if err != nil {
					return err
				}
				defer c.Close()
				n, err := io.Copy(io.Discard, c)
				if err != nil || n != wgBenchBytes {
					return fmt.Errorf("download: n=%d err=%v", n, err)
				}
				return nil
			})
		}
		if err := errg.Wait(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWireguardUpload streams wgBenchBytes from the client to the sink
// through the tunnel (client -> WG inbound is the TCP receiver).
func BenchmarkWireguardUpload(b *testing.B) {
	l, dest := listenTCP()
	defer l.Close()
	done := make(chan int64, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				done <- n
			}()
		}
	}()
	port, closer := wgBenchSetup(dest)
	defer closer()

	payload := make([]byte, wgBenchBytes)
	b.SetBytes(wgBenchBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+port.String())
		common.Must(err)
		if _, err := c.Write(payload); err != nil {
			b.Fatalf("upload write: %v", err)
		}
		c.(*net.TCPConn).CloseWrite()
		n := <-done
		c.Close()
		if n != wgBenchBytes {
			b.Fatalf("upload: sink got %d", n)
		}
	}
}

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
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

const xhttpBenchBytes = 64 << 20

// xhttpBenchSetup starts client (dokodemo -> VLESS/XHTTP outbound) and server
// (VLESS/XHTTP inbound -> dokodemo -> dest) instances in-process and returns
// the client dokodemo port plus a closer.
func xhttpBenchSetup(dest xnet.Destination, mode string) (xnet.Port, func()) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()
	quietLog := serial.ToTypedMessage(&log.Config{
		ErrorLogLevel: clog.Severity_Error,
		ErrorLogType:  log.LogType_Console,
	})

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{quietLog},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(serverPort)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "splithttp",
						TransportSettings: []*internet.TransportConfig{{
							ProtocolName: "splithttp",
							Settings:     serial.ToTypedMessage(&splithttp.Config{Mode: mode}),
						}},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{{
						Account: serial.ToTypedMessage(&vless.Account{Id: userID.String()}),
					}},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	clientConfig := &core.Config{
		App: []*serial.TypedMessage{quietLog},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(clientPort)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  xnet.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []xnet.Network{xnet.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "splithttp",
						TransportSettings: []*internet.TransportConfig{{
							ProtocolName: "splithttp",
							Settings:     serial.ToTypedMessage(&splithttp.Config{Mode: mode}),
						}},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								PinnedPeerCertSha256: [][]byte{ctHash[:]},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{Id: userID.String()}),
						},
					},
				}),
			},
		},
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

// BenchmarkXHTTPDownload streams xhttpBenchBytes from the sink server to the
// client through the tunnel.
func BenchmarkXHTTPDownload(b *testing.B) {
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := xhttpBenchSetup(dest, "stream-up")
	defer closer()

	b.SetBytes(xhttpBenchBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+port.String())
		common.Must(err)
		n, err := io.Copy(io.Discard, c)
		c.Close()
		if err != nil || n != xhttpBenchBytes {
			b.Fatalf("download: n=%d err=%v", n, err)
		}
	}
}

// BenchmarkXHTTPDownloadParallel downloads over several connections at once,
// which shows whether a single stream is bound by latency or by CPU.
func BenchmarkXHTTPDownloadParallel(b *testing.B) {
	const streams = 4
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := xhttpBenchSetup(dest, "stream-up")
	defer closer()

	b.SetBytes(streams * xhttpBenchBytes)
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
				if err != nil || n != xhttpBenchBytes {
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

// BenchmarkXHTTPUpload streams xhttpBenchBytes from the client to the sink
// through the tunnel.
func BenchmarkXHTTPUpload(b *testing.B) {
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
	port, closer := xhttpBenchSetup(dest, "stream-up")
	defer closer()

	payload := make([]byte, xhttpBenchBytes)
	b.SetBytes(xhttpBenchBytes)
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
		if n != xhttpBenchBytes {
			b.Fatalf("upload: sink got %d", n)
		}
	}
}

// BenchmarkXHTTPPacketUpDownload is BenchmarkXHTTPDownload with mode
// "packet-up" instead of "stream-up".
func BenchmarkXHTTPPacketUpDownload(b *testing.B) {
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := xhttpBenchSetup(dest, "packet-up")
	defer closer()

	b.SetBytes(xhttpBenchBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+port.String())
		common.Must(err)
		n, err := io.Copy(io.Discard, c)
		c.Close()
		if err != nil || n != xhttpBenchBytes {
			b.Fatalf("download: n=%d err=%v", n, err)
		}
	}
}

package scenarios

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	hysteriatransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

type hysteriaOptions struct {
	masks         []*serial.TypedMessage
	logLevel      clog.Severity
	clientUDPPort net.Port // adds a UDP dokodemo inbound on the client
	udpDest       net.Destination
}

// hysteriaConfigs builds a Hysteria inbound forwarding to dest and a client
// whose dokodemo inbound on clientPort goes through the Hysteria outbound.
func hysteriaConfigs(dest net.Destination, serverPort, clientPort net.Port, opts hysteriaOptions) (*core.Config, *core.Config) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	const auth = "test-auth"
	logLevel := opts.logLevel
	if logLevel == clog.Severity_Unknown {
		logLevel = clog.Severity_Debug
	}
	quietLog := serial.ToTypedMessage(&log.Config{
		ErrorLogLevel: logLevel,
		ErrorLogType:  log.LogType_Console,
	})

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{quietLog},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "hysteria",
						TransportSettings: []*internet.TransportConfig{{
							ProtocolName: "hysteria",
							Settings:     serial.ToTypedMessage(&hysteriatransport.Config{}),
						}},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
							}),
						},
						Udpmasks: opts.masks,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&hysteria.ServerConfig{
					Users: []*protocol.User{{
						Email:   "hy@example.com",
						Account: serial.ToTypedMessage(&account.Account{Auth: auth}),
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

	clientInbounds := []*core.InboundHandlerConfig{
		{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		},
	}
	if opts.clientUDPPort != 0 {
		clientInbounds = append(clientInbounds, &core.InboundHandlerConfig{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(opts.clientUDPPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(opts.udpDest.Address),
				RewritePort:     uint32(opts.udpDest.Port),
				AllowedNetworks: []net.Network{net.Network_UDP},
			}),
		})
	}
	clientConfig := &core.Config{
		App:     []*serial.TypedMessage{quietLog},
		Inbound: clientInbounds,
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "hysteria",
						TransportSettings: []*internet.TransportConfig{{
							ProtocolName: "hysteria",
							Settings:     serial.ToTypedMessage(&hysteriatransport.Config{Auth: auth}),
						}},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								PinnedPeerCertSha256: [][]byte{ctHash[:]},
							}),
						},
						Udpmasks: opts.masks,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&hysteria.ClientConfig{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
					},
				}),
			},
		},
	}
	return serverConfig, clientConfig
}

// TestHysteriaSalamander runs TCP through a Hysteria outbound -> inbound pair
// whose UDP is wrapped by the salamander mask, which exercises the
// out-of-band capable mask wrapper that quic-go uses for its fast path.
func TestHysteriaSalamander(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	udpServer := udp.Server{
		MsgProcessor: xor,
	}
	udpDest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	serverPort := udp.PickPort()
	clientPort := tcp.PickPort()
	clientUDPPort := udp.PickPort()
	serverConfig, clientConfig := hysteriaConfigs(dest, serverPort, clientPort, hysteriaOptions{
		masks:         []*serial.TypedMessage{serial.ToTypedMessage(&salamander.Config{Password: "1234"})},
		clientUDPPort: clientUDPPort,
		udpDest:       udpDest,
	})

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var errg errgroup.Group
	for i := 0; i < 10; i++ {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*20))
		errg.Go(testUDPConn(clientUDPPort, 1024, time.Second*20))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

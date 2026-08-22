package scenarios

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"golang.org/x/sync/errgroup"
)

const hyBenchBytes = 64 << 20

// hyBenchSetup starts client (dokodemo -> Hysteria outbound) and server
// (Hysteria inbound -> freedom -> dest) instances in-process and returns the
// dokodemo port plus a closer.
func hyBenchSetup(dest xnet.Destination) (xnet.Port, func()) {
	serverPort := udp.PickPort()
	clientPort := tcp.PickPort()
	serverConfig, clientConfig := hysteriaConfigs(dest, serverPort, clientPort, hysteriaOptions{
		logLevel: clog.Severity_Error,
	})

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

// BenchmarkHysteriaDownload streams hyBenchBytes from the sink server to the
// client through the tunnel.
func BenchmarkHysteriaDownload(b *testing.B) {
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := hyBenchSetup(dest)
	defer closer()

	b.SetBytes(hyBenchBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+port.String())
		common.Must(err)
		n, err := io.Copy(io.Discard, c)
		c.Close()
		if err != nil || n != hyBenchBytes {
			b.Fatalf("download: n=%d err=%v", n, err)
		}
	}
}

// BenchmarkHysteriaDownloadParallel downloads over several connections at
// once, which shows whether a single stream is bound by latency or by CPU.
func BenchmarkHysteriaDownloadParallel(b *testing.B) {
	const streams = 4
	l, dest := listenTCP()
	defer l.Close()
	go serveDownloads(l)
	port, closer := hyBenchSetup(dest)
	defer closer()

	b.SetBytes(streams * hyBenchBytes)
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
				if err != nil || n != hyBenchBytes {
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

// BenchmarkHysteriaUpload streams hyBenchBytes from the client to the sink
// through the tunnel.
func BenchmarkHysteriaUpload(b *testing.B) {
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
	port, closer := hyBenchSetup(dest)
	defer closer()

	payload := make([]byte, hyBenchBytes)
	b.SetBytes(hyBenchBytes)
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
		if n != hyBenchBytes {
			b.Fatalf("upload: sink got %d", n)
		}
	}
}

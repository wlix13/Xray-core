package splithttp

import (
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

// WriteMultiBuffer lets the server side write a whole batch as a few large
// frames; the other writers keep their per-buffer size limits.
func (c *splitConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w, ok := c.writer.(*httpServerConn); ok {
		return w.WriteMultiBuffer(mb)
	}
	return (&buf.SequentialWriter{Writer: c.writer}).WriteMultiBuffer(mb)
}

func (c *splitConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

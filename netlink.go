//go:build linux

package netlink

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Generic Netlink Client

// Sender sends a netlink message and returns the sequence number used
// in the message and an error if it occurred.
type Sender interface {
	Send(msg syscall.NetlinkMessage) (seq uint32, err error)
}

// Receiver receives data from the netlink socket and uses the provided
// parser to convert the raw bytes to NetlinkMessages.
type Receiver interface {
	Receive() ([]syscall.NetlinkMessage, error)
}

// NetlinkSendReceiver combines the Send and Receive into one interface.
type NetlinkSendReceiver interface {
	io.Closer
	Sender
	Receiver
}

// Client is a generic client for sending and receiving netlink messages.
type Client struct {
	fd      int              // File descriptor used for communication.
	src     syscall.Sockaddr // Local socket address.
	dest    syscall.Sockaddr // Remote socket address (client assumes the dest is the kernel).
	pid     uint32           // Port ID of the local socket(In netlink, it's local process id).
	seq     uint32           // Sequence number used in outgoing messages.
	readBuf []byte
}

// NewClient creates a new Client. It creates a socket and binds
// it. readBuf is an optional byte buffer used for reading data from the socket.
// The size of the buffer limits the maximum message size the can be read. If no
// buffer is provided one will be allocated using the OS page size.
//
// The returned Client must be closed with Close() when finished.
func NewClient(proto int, groups uint32, readBuf []byte) (*Client, error) {
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}

	src := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}
	if err = syscall.Bind(s, src); err != nil {
		syscall.Close(s)
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	pid, err := getPortID(s)
	if err != nil {
		syscall.Close(s)
		return nil, err
	}

	if len(readBuf) == 0 {
		// Default size used in libnl.
		readBuf = make([]byte, os.Getpagesize())
	}

	return &Client{
		fd:      s,
		src:     src,
		dest:    &syscall.SockaddrNetlink{},
		pid:     pid,
		readBuf: readBuf,
	}, nil
}

// getPortID gets the kernel assigned port ID (PID) of the local netlink socket.
// The kernel assigns the processes PID to the first socket then assigns arbitrary values
// to any follow-on sockets. See man netlink for details.
func getPortID(fd int) (uint32, error) {
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, err
	}

	addr, ok := address.(*syscall.SockaddrNetlink)
	if !ok {
		return 0, errors.New("unexpected socket address type")
	}

	return addr.Pid, nil
}

// Send sends a netlink message and returns the sequence number used
// in the message and an error if it occurred. If the PID is not set then
// the value will be populated automatically (recommended).
func (c *Client) Send(msg syscall.NetlinkMessage) (uint32, error) {
	return c.send(msg, 0)
}

func (c *Client) send(msg syscall.NetlinkMessage, flags int) (uint32, error) {
	if msg.Header.Pid == 0 {
		msg.Header.Pid = c.pid
	}

	if msg.Header.Seq == 0 {
		msg.Header.Seq = atomic.AddUint32(&c.seq, 1)
	}
	to := &syscall.SockaddrNetlink{}
	return msg.Header.Seq, syscall.Sendto(c.fd, serialize(msg), flags, to)
}

func serialize(msg syscall.NetlinkMessage) []byte {
	msg.Header.Len = uint32(syscall.SizeofNlMsghdr + len(msg.Data))
	b := make([]byte, msg.Header.Len)
	*(*syscall.NlMsghdr)(unsafe.Pointer(&b[0])) = msg.Header
	copy(b[syscall.SizeofNlMsghdr:], msg.Data)
	return b
}

// Receive receives data from the netlink socket and uses the provided
// parser to convert the raw bytes to NetlinkMessages. See Receiver docs.
func (c *Client) Receive() ([]syscall.NetlinkMessage, error) {
	// XXX (akroh): A possible enhancement is to use the MSG_PEEK flag to
	// check the message size and increase the buffer size to handle it all.
	nr, from, err := syscall.Recvfrom(c.fd, c.readBuf, 0)
	if err != nil {
		// EAGAIN or EWOULDBLOCK will be returned for non-blocking reads where
		// the read would normally have blocked.
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, fmt.Errorf("not enough bytes (%v) received to form a netlink header", nr)
	}
	fromNetlink, ok := from.(*syscall.SockaddrNetlink)
	if !ok || fromNetlink.Pid != 0 {
		// Spoofed packet received on audit netlink socket.
		return nil, errors.New("message received was not from the kernel")
	}

	buf := c.readBuf[:nr]

	return syscall.ParseNetlinkMessage(buf)
}

// Close closes the netlink client's raw socket.
func (c *Client) Close() error {
	return syscall.Close(c.fd)
}

// Netlink Error Code Handling

// ParseNetlinkError parses the errno from the data section of a
// syscall.NetlinkMessage. If netlinkData is less than 4 bytes an error
// describing the problem will be returned.
func ParseNetlinkError(netlinkData []byte) error {
	if len(netlinkData) >= 4 {
		errno := -*(*int32)(unsafe.Pointer(&netlinkData[0]))
		if errno == 0 {
			return nil
		}
		return syscall.Errno(errno)
	}
	return errors.New("received netlink error (data too short to read errno)")
}

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"crypto/tls"
	_ "encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	_ "os"
	"sync"

	"github.com/apcera/gssapi"
	"github.com/mmitton/asn1-ber"
)

// LDAP Connection
type Conn struct {
	conn  net.Conn
	isSSL bool
	Debug bool

	chanResults        map[uint64]chan *ber.Packet
	chanProcessMessage chan *messagePacket
	chanMessageID      chan uint64

	gss_lib           *gssapi.Lib
	gss_context       *gssapi.CtxId
	gss_layers_limit  *gssapi.Buffer
	gss_encrypted     bool
	gss_qop           gssapi.QOP
	gss_wrap_overhead int
	gss_buffer        []byte
	gss_buffer_pos    int

	closeLock sync.Mutex
}

func (l *Conn) Write(p []byte) (int, error) {
	if l.isSSL || l.gss_context == nil {
		return l.conn.Write(p)
	}
	return l.saslWrite(p)
}

func (l *Conn) saslWrite(p []byte) (int, error) {
	var _in, _out *gssapi.Buffer
	var err error
	if _in, err = l.gss_lib.MakeBufferBytes(p); err == nil {
		if _, _out, err = l.gss_context.Wrap(l.gss_encrypted, l.gss_qop, _in); err == nil {
			lenbuf := make([]byte, 4)
			for i := 0; i < 4; i++ {
				lenbuf[i] = byte(_out.Length() >> uint(24-i*8))
			}
			if j, e := l.conn.Write(lenbuf); e != nil || j < len(lenbuf) {
				return 0, e
			}
			for written := 0; written < _out.Length(); {
				if j, e := l.conn.Write(_out.Bytes()[written:]); e != nil {
					return written, e
				} else {
					written += j
				}
			}
		}
	} else {
		return 0, err
	}
	return len(p), nil
}

func (l *Conn) saslFillBuffer(buflen int, preFetched []byte) (err error) {
	if l.gss_buffer_pos < len(l.gss_buffer) {
		return errors.New("?")
	}
	tmpbuf := make([]byte, buflen)
	copy(tmpbuf, preFetched)
	cursize := len(preFetched)
	for cursize < buflen {
		//fmt.Fprintf(os.Stderr, "reading %d bytes from real conn [prefetched:%d,cursize=%d]\n", cap(tmpbuf)-cursize, preFetched, cursize)
		if n, err := l.conn.Read(tmpbuf[cursize:]); err != nil {
			return err
		} else {
			cursize += n
		}
	}
	if gssapi_wrapped_buffer, err := l.gss_context.MakeBufferBytes(tmpbuf); err == nil {
		if gssapi_unwrapped_buffer, _, _, err := l.gss_context.Unwrap(gssapi_wrapped_buffer); err == nil {
			l.gss_buffer = gssapi_unwrapped_buffer.Bytes()
			l.gss_buffer_pos = 0
		}
	}
	return err
}

func sizeRead(buf []byte) int {
	return (int(buf[0]) << 24) + (int(buf[1]) << 16) + (int(buf[2]) << 8) + (int(buf[3]) << 0)
}

func (l *Conn) Read(p []byte) (n int, e error) {
	//fmt.Fprintf(os.Stderr, "reading %d bytes from %v\n", cap(p), l.conn)
	//fmt.Fprintf(os.Stderr, "buffer:%d/%d\n", l.gss_buffer_pos, cap(l.gss_buffer))
	if l.gss_buffer_pos < len(l.gss_buffer) {
		return l.saslReadBuffer(p)
	}
	if l.conn == nil {
		return 0, io.EOF
	}
	if n, e = l.conn.Read(p); e != nil {
		return
	}
	if l.isSSL || l.gss_context == nil {
		return
	}
	if n < 4 {
		p2 := make([]byte, 4)
		copy(p2, p)
		if _, e = l.conn.Read(p2[n:]); e != nil {
			return
		}
		return l.saslRead(p, sizeRead(p2), []byte{})
	}
	return l.saslRead(p, sizeRead(p), p[4:])
}

func (l *Conn) saslReadBuffer(p []byte) (int, error) {
	if l.gss_buffer_pos >= len(l.gss_buffer) {
		return 0, errors.New("no buffered data")
	}
	bytesToCopy := len(p)
	if bytesToCopy >= len(l.gss_buffer)-l.gss_buffer_pos {
		bytesToCopy = len(l.gss_buffer) - l.gss_buffer_pos
	}
	copy(p, l.gss_buffer[l.gss_buffer_pos:l.gss_buffer_pos+bytesToCopy])
	l.gss_buffer_pos += bytesToCopy
	return bytesToCopy, nil
}

func (l *Conn) saslRead(p []byte, buflen int, preFetched []byte) (int, error) {
	//fmt.Fprintf(os.Stderr, "SASL reading: %d bytes\n", buflen)
	if l.gss_buffer_pos >= len(l.gss_buffer) {
		if err := l.saslFillBuffer(buflen, preFetched); err != nil {
			return 0, err
		}
	}
	return l.saslReadBuffer(p)
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Conn for the connection.
func Dial(network, addr string) (*Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.start()
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then sets up SSL connection and returns a new Conn for the connection.
func DialSSL(network, addr string) (*Conn, error) {
	c, err := tls.Dial(network, addr, nil)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.isSSL = true

	conn.start()
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then starts a TLS session and returns a new Conn for the connection.
func DialTLS(network, addr string) (*Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)

	err = conn.startTLS()
	if err != nil {
		conn.Close()
		return nil, NewError(ErrorNetwork, err)
	}
	conn.start()
	return conn, nil
}

// NewConn returns a new Conn using conn for network I/O.
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn:               conn,
		isSSL:              false,
		Debug:              false,
		chanResults:        map[uint64]chan *ber.Packet{},
		chanProcessMessage: make(chan *messagePacket),
		chanMessageID:      make(chan uint64),
	}
}

func (l *Conn) start() {
	go l.reader()
	go l.processMessages()
}

func (l *Conn) Peer() net.Addr {
	return l.conn.RemoteAddr()
}

// Close closes the connection.
func (l *Conn) Close() error {
	l.closeLock.Lock()
	defer l.closeLock.Unlock()

	l.sendProcessMessage(&messagePacket{Op: MessageQuit})

	if l.conn != nil {
		err := l.conn.Close()
		if err != nil {
			return NewError(ErrorNetwork, err)
		}
		l.conn = nil
	}
	return nil
}

// Returns the next available messageID
func (l *Conn) nextMessageID() (messageID uint64) {
	defer func() {
		if r := recover(); r != nil {
			messageID = 0
		}
	}()
	messageID = <-l.chanMessageID
	return
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *Conn) startTLS() error {
	messageID := l.nextMessageID()

	if l.isSSL {
		return NewError(ErrorNetwork, errors.New("Already encrypted"))
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	startTLS := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	startTLS.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	packet.AppendChild(startTLS)
	if l.Debug {
		ber.PrintPacket(packet)
	}

	_, err := l.conn.Write(packet.Bytes())
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	packet, err = ber.ReadPacket(l.conn)
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Children[0].Value.(uint64) == 0 {
		conn := tls.Client(l.conn, nil)
		l.isSSL = true
		l.conn = conn
	}

	return nil
}

const (
	MessageQuit     = 0
	MessageRequest  = 1
	MessageResponse = 2
	MessageFinish   = 3
)

type messagePacket struct {
	Op        int
	MessageID uint64
	Packet    *ber.Packet
	Channel   chan *ber.Packet
}

func (l *Conn) sendMessage(p *ber.Packet) (out chan *ber.Packet, err error) {
	message_id := p.Children[0].Value.(uint64)
	out = make(chan *ber.Packet)

	if l.chanProcessMessage == nil {
		err = NewError(ErrorNetwork, errors.New("Connection closed"))
		return
	}
	message_packet := &messagePacket{Op: MessageRequest, MessageID: message_id, Packet: p, Channel: out}
	l.sendProcessMessage(message_packet)
	return
}

func (l *Conn) processMessages() {
	defer l.closeAllChannels()

	var message_id uint64 = 1
	var message_packet *messagePacket
	for {
		select {
		case l.chanMessageID <- message_id:
			if l.conn == nil {
				return
			}
			message_id++
		case message_packet = <-l.chanProcessMessage:
			if l.conn == nil {
				return
			}
			switch message_packet.Op {
			case MessageQuit:
				// Close all channels and quit
				if l.Debug {
					fmt.Printf("Shutting down\n")
				}
				return
			case MessageRequest:
				// Add to message list and write to network
				if l.Debug {
					fmt.Printf("Sending message %d\n", message_packet.MessageID)
				}
				l.chanResults[message_packet.MessageID] = message_packet.Channel
				buf := message_packet.Packet.Bytes()
				for len(buf) > 0 {
					//n, err := l.conn.Write(buf)
					n, err := l.Write(buf)
					if err != nil {
						if l.Debug {
							fmt.Printf("Error Sending Message: %s\n", err.Error())
						}
						return
					}
					if n == len(buf) {
						break
					}
					buf = buf[n:]
				}
			case MessageResponse:
				// Pass back to waiting goroutine
				if l.Debug {
					fmt.Printf("Receiving message %d\n", message_packet.MessageID)
				}
				chanResult := l.chanResults[message_packet.MessageID]
				if chanResult == nil {
					fmt.Printf("Unexpected Message Result: %d\n", message_id)
					ber.PrintPacket(message_packet.Packet)
				} else {
					chanResult <- message_packet.Packet
				}
			case MessageFinish:
				// Remove from message list
				if l.Debug {
					fmt.Printf("Finished message %d\n", message_packet.MessageID)
				}
				delete(l.chanResults, message_packet.MessageID)
			}
		}
	}
}

func (l *Conn) closeAllChannels() {
	for MessageID, Channel := range l.chanResults {
		if l.Debug {
			fmt.Printf("Closing channel for MessageID %d\n", MessageID)
		}
		close(Channel)
		delete(l.chanResults, MessageID)
	}
	close(l.chanMessageID)
	l.chanMessageID = nil

	close(l.chanProcessMessage)
	l.chanProcessMessage = nil
}

func (l *Conn) finishMessage(MessageID uint64) {
	message_packet := &messagePacket{Op: MessageFinish, MessageID: MessageID}
	l.sendProcessMessage(message_packet)
}

func (l *Conn) reader() {
	defer l.Close()
	for {
		//p, err := ber.ReadPacket(l.conn)
		p, err := ber.ReadPacket(l)
		if err != nil {
			if l.Debug {
				fmt.Printf("ldap.reader: %s\n", err.Error())
			}
			return
		}

		addLDAPDescriptions(p)

		message_id := p.Children[0].Value.(uint64)
		message_packet := &messagePacket{Op: MessageResponse, MessageID: message_id, Packet: p}
		if l.chanProcessMessage != nil {
			l.chanProcessMessage <- message_packet
		} else {
			fmt.Printf("ldap.reader: Cannot return message\n")
			return
		}
	}
}

func (l *Conn) sendProcessMessage(message *messagePacket) {
	if l.chanProcessMessage != nil {
		//go func(m *messagePacket) { l.chanProcessMessage <- message }(message)
		l.chanProcessMessage <- message
	}
}

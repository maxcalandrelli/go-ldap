// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Bind functionality
package ldap

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/apcera/gssapi"
	"github.com/mmitton/asn1-ber"
)

func bindPacketHeader(username string) *ber.Packet {
	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, username, "User Name"))
	return bindRequest
}

func bindPacketSimple(username, password string) *ber.Packet {
	bindRequest := bindPacketHeader(username)
	bindRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, password, "Password"))
	return bindRequest
}

func bindPacketGSSAPI(token []byte) *ber.Packet {
	bindRequest := bindPacketHeader("")
	sasl_auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SaslCredentials(RFC4511)")
	sasl_auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, "GSSAPI", "SASL-Mechanism"))
	if len(token) > 0 {
		sasl_auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(token), "Token"))
	}
	bindRequest.AppendChild(sasl_auth)
	return bindRequest
}

const (
	SASLDone = LDAPResultOther + 1
	SASLUnexpected
)

type SASLMessage struct {
	Packet []byte
	Err    *Error
}

func (l *Conn) start_bind(c chan SASLMessage) {
	for reply := SASLMessage(SASLMessage{}); reply.Err == nil; c <- reply {
		select {
		case msg, ok := <-c:
			if !ok || msg.Err != nil || msg.Packet == nil {
				reply.Err = &Error{ResultCode: SASLUnexpected}
			}
			reply.Packet, reply.Err = func() ([]byte, *Error) {
				messageID := l.nextMessageID()
				packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
				packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
				pbuf := msg.Packet
				packet.AppendChild(bindPacketGSSAPI(pbuf))
				//fmt.Fprintf(os.Stderr, ">>>>%d bytes (pbuf:%d):\n%s", packet.DataLength(), len(pbuf), hex.Dump(packet.Bytes()))
				channel, err := l.sendMessage(packet)
				if err != nil {
					return nil, &Error{ResultCode: ErrorNetwork, Err: err}
				}
				if channel == nil {
					return nil, &Error{ResultCode: ErrorNetwork, Err: errors.New("Could not send message")}
				}
				defer l.finishMessage(messageID)
				packet = <-channel
				if packet == nil {
					return nil, &Error{ResultCode: ErrorNetwork, Err: errors.New("Could not retrieve response")}
				}
				result_code, result_description := GetLDAPResultCode(packet)
				switch result_code {
				case LDAPResultSaslBindInProgress:
					return packet.Bytes(), nil
				case 0:
					return nil, &Error{ResultCode: SASLDone}
				default:
					return nil, &Error{ResultCode: result_code, Err: errors.New(result_description)}
				}
			}()
		}
	}
}

func (l *Conn) do_bind(authentication *ber.Packet) error {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(authentication)

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	if channel == nil {
		return NewError(ErrorNetwork, errors.New("Could not send message"))
	}
	defer l.finishMessage(messageID)
	packet = <-channel

	if packet == nil {
		return NewError(ErrorNetwork, errors.New("Could not retrieve response"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		//fmt.Fprintf(os.Stderr, "%s", hex.Dump(packet.Bytes()))
		ber.PrintPacket(packet)
	}

	result_code, result_description := getLDAPResultCode(packet)

	if result_code == LDAPResultSaslBindInProgress {

	} else if result_code != 0 {
		return NewError(result_code, errors.New(result_description))
	}

	return nil
}

func errorFunc(e error) error {
	if true {
		panic(e)
	}
	return e
}

func getKrbParams(ctx *gssapi.CtxId, token *gssapi.Buffer) (layersAndLimit *gssapi.Buffer, securityLayers byte, maxMessageSize int, encrypted bool, qop gssapi.QOP, err error) {
	layersAndLimit, encrypted, qop, err = ctx.Unwrap(token)
	if err == nil && layersAndLimit.Length() != 4 {
		err = errors.New("unexpected buffer size")
	}
	if err == nil {
		maxMessageSize = 0
		for _, b := range layersAndLimit.Bytes()[1:] {
			maxMessageSize = maxMessageSize<<8 + int(b)
		}
		securityLayers = layersAndLimit.Bytes()[0]
	}
	//fmt.Fprintf(os.Stderr, "layers=%v maxsize=%v enc=%v qop=%v\n", securityLayers, maxMessageSize, encrypted, qop)
	return
}

func (l *Conn) BindGSSAPI(token *gssapi.Buffer) error {
	var (
		err      error
		buf      *gssapi.Buffer
		name     *gssapi.Name
		mechs    *gssapi.OIDSet
		ctx      *gssapi.CtxId
		mech     *gssapi.OID
		flags    uint32
		cred     *gssapi.CredId
		bindings gssapi.ChannelBindings
		life     time.Duration
	)
	l.gss_lib, err = gssapi.Load(&gssapi.Options{})
	if err != nil {
		return errorFunc(err)
	}
	//defer lib.Unload()
	servername := ""
	if host, _, err := net.SplitHostPort(l.Peer().String()); err == nil {
		servername = host
	}
	buf, err = l.gss_lib.MakeBufferString(fmt.Sprintf("ldap@%s", servername))
	if err != nil {
		return errorFunc(err)
	}
	defer buf.Release()
	name, err = buf.Name(l.gss_lib.GSS_C_NT_HOSTBASED_SERVICE)
	if err != nil {
		return errorFunc(err)
	}
	defer name.Release()
	mechs, err = name.InquireMechs()
	if err != nil {
		return errorFunc(err)
	}
	defer mechs.Release()

	ctx = l.gss_lib.GSS_C_NO_CONTEXT
	mech = l.gss_lib.GSS_C_NO_OID
	flags = uint32(gssapi.GSS_C_MUTUAL_FLAG)
	cred = l.gss_lib.GSS_C_NO_CREDENTIAL
	bindings = l.gss_lib.GSS_C_NO_CHANNEL_BINDINGS
	life = time.Duration(0)
	if token == nil {
		token = l.gss_lib.GSS_C_NO_BUFFER
	}
	sasl_channel := make(chan SASLMessage)
	go l.start_bind(sasl_channel)
	challenge := SASLMessage{}
	last_round := false
	for {
		if !last_round {
			ctx, mech, token, flags, life, err = l.gss_lib.InitSecContext(cred, ctx, name, mech, flags, life, bindings, token)
			if err != nil && err != gssapi.ErrContinueNeeded && err != gssapi.ErrContinueNeeded {
				err = errors.New(fmt.Sprintf("%s (%s)", err.Error(), servername))
				return errorFunc(errors.New(err.Error()))
			}
			if token.Length() > 0 {
				challenge = SASLMessage{Packet: token.Bytes()}
			} else {
				challenge = SASLMessage{}
			}
		}
		sasl_channel <- challenge
		answer := <-sasl_channel
		if answer.Err != nil {
			if answer.Err.ResultCode == SASLDone {
				l.gss_context = ctx
				return nil
			}
			return errorFunc(answer.Err.Err)
		}
		if last_round {
			return errors.New("SASLDone not received")
		}
		switch err {
		case nil:
			server_token_blob := Access(ber.DecodePacket(answer.Packet), []int{1, 3}).Data.Bytes()
			bb := make([]byte, len(server_token_blob))
			copy(bb, server_token_blob)
			token, err = l.gss_lib.MakeBufferBytes(bb)
			l.gss_layers_limit, _, _, l.gss_encrypted, l.gss_qop, err = getKrbParams(ctx, token)
			l.gss_wrap_overhead = token.Length() - l.gss_layers_limit.Length()
			if err != nil {
				return errorFunc(err)
			}
			_, token, err = ctx.Wrap(l.gss_encrypted, l.gss_qop, l.gss_layers_limit)
			challenge = SASLMessage{Packet: token.Bytes()}
			last_round = true
		case gssapi.ErrContinueNeeded:
			server_token_blob := Access(ber.DecodePacket(answer.Packet), []int{1, 3}).Data
			token, err = l.gss_lib.MakeBufferBytes(server_token_blob.Bytes())
		default:
			return errorFunc(err)
		}
	}
}

func (l *Conn) BindSimple(username, password string) error {
	return l.do_bind(bindPacketSimple(username, password))
}

func (l *Conn) Bind(username, password string) error {
	messageID := l.nextMessageID()

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, username, "User Name"))
	bindRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, password, "Password"))
	packet.AppendChild(bindRequest)

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	if channel == nil {
		return NewError(ErrorNetwork, errors.New("Could not send message"))
	}
	defer l.finishMessage(messageID)
	packet = <-channel

	if packet == nil {
		return NewError(ErrorNetwork, errors.New("Could not retrieve response"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(packet)
	}

	result_code, result_description := getLDAPResultCode(packet)
	if result_code != 0 {
		return NewError(result_code, errors.New(result_description))
	}

	return nil
}

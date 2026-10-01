package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
)

const (
	socks5Version = uint8(5)
	ipv4Addr      = uint8(1)
	fqdnAddr      = uint8(3)
	ipv6Addr      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreacheable
	hostUnreacheable
)

type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

type Config struct {
	Resolver NameResolver
}

type Server struct {
	config *Config
}

type Request struct {
	DestAddr *AddrSpec
}

type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.IP
}

func (s *Server) handleRequest(req *Request, conn conn) error {
	ctx := context.TODO()

	dest := req.DestAddr
	if dest.FQDN != "" {
		ctx_, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreacheable, nil); err != nil {
				return fmt.Errorf("failed to send reply")
			}
			return fmt.Errorf("failed to resolve destination")
		}
		ctx = ctx_
		dest.IP = addr
	}
	return nil
}

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Addr
		addrBody = []byte{0, 0, 0, 0}
		addrPort = uint16(0)

	case addr.FQDN != "":
		addrType = fqdnAddr
		addrBody = append(
			[]byte{byte(len(addr.FQDN))},
			[]byte(addr.FQDN)...,
		)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Addr
		addrBody = addr.IP.To4()
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Addr
		addrBody = addr.IP.To16()
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("unrec addr type")
	}

	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	_, err := w.Write(msg)
	return err
}

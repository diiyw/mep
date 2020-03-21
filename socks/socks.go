package socks

import (
	"bytes"
	"github.com/diiyw/mep/stream"
	"log"
	"net"
	"strconv"
	"strings"
)

const (

	// version
	V4 byte = 0x04
	V5      = 0x05

	// command
	CONNECT = 0x01
	BIND    = 0x02
	UDP     = 0x03

	V5NoAuth = 0x00
)

func Listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Listen:", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		ver := make([]byte, 1)
		_, err = conn.Read(ver)
		if err != nil {
			_ = conn.Close()
			continue
		}
		if ver[0] == V4 {
			go handleSocks4(conn)
		}
		go handleSocks5(conn, addr)
	}
}

func handleSocks4(conn net.Conn) {
	defer conn.Close()
	s4 := make([]byte, 8)
	if _, err := conn.Read(s4); err != nil {
		return
	}
	s4 = bytes.TrimRight(s4, string([]byte{0}))
	if len(s4) < 7 {
		// may be s4[0] is an port
		// curl bug
		s4 = append([]byte{CONNECT, 0x00}, s4...)
	}
	if s4[0] == CONNECT {
		ip := net.IPv4(s4[3], s4[4], s4[5], s4[6])
		port := strconv.Itoa(int(s4[1])<<8 + int(s4[2]))
		remoteAddr := ip.String() + ":" + port
		dstConn, err := net.Dial("tcp", remoteAddr)
		if err != nil {
			return
		}
		resp := make([]byte, 8)
		resp = append([]byte{0x00, 0x5a}, s4[1], s4[2], s4[3], s4[4], s4[5], s4[6])
		_, err = conn.Write(resp)
		if err != nil {
			return
		}
		err = stream.Copy(dstConn, conn)
		if err != nil {
			log.Println(err)
		}
	}
}

func handleSocks5(conn net.Conn, addr string) {
	defer conn.Close()
	s5 := make([]byte, 1)
	n, err := conn.Read(s5)
	if err != nil || n != 1 {
		return
	}
	// Read methods
	method := make([]byte, int(s5[0]))
	if _, err := conn.Read(method); err != nil {
		return
	}
	// todo rule set
	// Response (all permit now)
	if _, err = conn.Write([]byte{V5, V5NoAuth}); err != nil {
		return
	}
	// The next request
	b := make([]byte, 512)
	n, err = conn.Read(b)
	if err != nil {
		return
	}
	b = b[:n]
	// Version
	if b[0] != V5 {
		return
	}
	// CONNECT Command
	if b[1] == CONNECT {
		var (
			host = getHost(b)
			port string
		)
		if host == "" {
			return
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))
		proxy, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			return
		}
		defer proxy.Close()
		// Successes
		conn.Write([]byte{V5, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		_ = stream.Copy(conn, proxy)
	}
	// BIND Command
	if b[1] == BIND {
		return
	}
	// UDP ASSOCIATE  Command
	if b[1] == UDP {
		resp := make([]byte, 10)
		randAddr, err := net.ResolveTCPAddr("tcp", ":0")
		if err != nil {
			return
		}
		listener, err := net.ListenTCP("tcp", randAddr)
		if err != nil {
			return
		}
		port, err := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])
		if err != nil {
			return
		}
		resp[0], resp[1], resp[2], resp[3] = V5, 0x00, 0x00, 0x01
		copy(resp[4:], net.ParseIP(strings.Split(addr, ":")[0]).To4())
		resp[8], resp[9] = byte(port>>8), byte(port)
		_, err = conn.Write(resp)
		if err != nil {
			return
		}
		for {
			udpConn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleSocks5UDP(conn, udpConn, resp)
		}
	}
}

func handleSocks5UDP(conn, udpConn net.Conn, resp []byte) {

}

func getHost(b []byte) string {
	n := len(b)
	var host string
	switch b[3] {
	case 0x01:
		//IPV4
		host = net.IPv4(b[4], b[5], b[6], b[7]).String()
	case 0x03:
		//Domain Name
		host = string(b[5 : n-2])
	case 0x04:
		//IPV6
		if len(b[4:]) != 16 {
			return ""
		}
		host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
	}
	return host
}

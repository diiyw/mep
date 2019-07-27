package socks

import (
	"log"
	"net"
	"strconv"
	"strings"
	"github.com/diiyw/mep/stream"
)

func ListenSocks(addr string) {
	if addr == "" {
		addr = "0.0.0.0:1080"
	}
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
			conn.Close()
			return
		}
		if ver[0] == 0x04 {
			go handleSocks4(conn, addr)
		} else if ver[0] == 0x05 {
			go handleSocks5(conn, addr)
		} else {
			conn.Close()
			return
		}

	}
}

func handleSocks4(conn net.Conn, addr string) {
	s4 := make([]byte, 8)
	if _, err := conn.Read(s4); err != nil {
		conn.Close()
		return
	}
	resp := make([]byte, 8)
	if s4[0] == 0x01 {
		ip := net.IPv4(s4[3], s4[4], s4[5], s4[6])
		port := strconv.Itoa(int(s4[1])<<8 + int(s4[2]))
		remoteAddr := ip.String() + ":" + port
		dstConn, err := net.Dial("tcp", remoteAddr)
		if err != nil {
			conn.Close()
			return
		}
		resp[0], resp[1] = 0x00, 0x5a
		_, err = conn.Write(resp)
		if err != nil {
			conn.Close()
			return
		}
		go stream.Copy(dstConn, conn)
		return
	}
}

func handleSocks5(conn net.Conn, addr string) {
	s5 := make([]byte, 1)
	n, err := conn.Read(s5)
	if err != nil || n != 1 {
		conn.Close()
		return
	}
	// Read methods
	method := make([]byte, int(s5[0]))
	if _, err := conn.Read(method); err != nil {
		conn.Close()
		return
	}
	// todo rule set
	// Response (all permit now)
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		conn.Close()
		return
	}
	// The second request
	b := make([]byte, 512)
	n, err = conn.Read(b)
	if err != nil {
		conn.Close()
		return
	}
	b = b[:n]
	// Version
	if b[0] != 0x05 {
		conn.Close()
		return
	}
	// CONNECT Command
	if b[1] == 0x01 {
		var (
			host = getHost(b)
			port string
		)
		if host == "" {
			conn.Close()
			return
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))
		proxy, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			return
		}
		defer proxy.Close()
		// Successes
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		if stream.Copy(conn, proxy) != nil {
			return
		}
		return
	}
	// BIND Command
	if b[1] == 0x02 {
		return
	}
	// UDP ASSOCIATE  Command
	if b[1] == 0x03 {
		resp := make([]byte, 10)
		randAddr, err := net.ResolveTCPAddr("tcp", ":0")
		if err != nil {
			conn.Close()
			return
		}
		listener, err := net.ListenTCP("tcp", randAddr)
		if err != nil {
			conn.Close()
			return
		}
		port, err := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])
		if err != nil {
			conn.Close()
			return
		}
		resp[0], resp[1], resp[2], resp[3] = 0x05, 0x00, 0x00, 0x01
		copy(resp[4:], []byte(net.ParseIP(strings.Split(addr, ":")[0]).To4()))
		resp[8], resp[9] = byte(port>>8), byte(port)
		_, err = conn.Write(resp)
		if err != nil {
			conn.Close()
			return
		}
		for {
			udpConn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleSocks5UDP(conn, udpConn, resp)
		}
		return
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

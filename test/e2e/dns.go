// Command dns answers every query with two A records in a fixed order.
// The first address is the one the supervisor must pin. The second is unused.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	udp, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	tcp, err := net.Listen("tcp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("dns listening")
	go serveTCP(tcp)
	buf := make([]byte, 1500)
	for {
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		resp := answer(buf[:n])
		if resp == nil {
			continue
		}
		if _, err := udp.WriteTo(resp, addr); err != nil {
			log.Print(err)
		}
	}
}

func serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			var nbuf [2]byte
			if _, err := io.ReadFull(c, nbuf[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(nbuf[:]))
			if n < 12 || n > 4096 {
				return
			}
			q := make([]byte, n)
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			resp := answer(q)
			if resp == nil {
				return
			}
			binary.BigEndian.PutUint16(nbuf[:], uint16(len(resp)))
			if _, err := c.Write(nbuf[:]); err != nil {
				return
			}
			_, _ = c.Write(resp)
		}(c)
	}
}

func answer(q []byte) []byte {
	qEnd, qtype, ok := questionEnd(q)
	if !ok {
		return nil
	}
	flags := binary.BigEndian.Uint16(q[2:4])
	flags |= 0x8080 // QR and RA
	flags &^= 0x0200
	ancount := 0
	if qtype == 1 {
		ancount = 2
	}
	resp := make([]byte, 0, qEnd+2*16)
	resp = append(resp, q[:12]...)
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[6:8], uint16(ancount))
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	resp = append(resp, q[12:qEnd]...)
	if qtype == 1 {
		resp = appendA(resp, []byte{203, 0, 113, 10})
		resp = appendA(resp, []byte{203, 0, 113, 11})
	}
	return resp
}

func questionEnd(q []byte) (int, uint16, bool) {
	if len(q) < 12 {
		return 0, 0, false
	}
	off := 12
	for {
		if off >= len(q) {
			return 0, 0, false
		}
		l := int(q[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			off += 2
			break
		}
		off += 1 + l
	}
	if off+4 > len(q) {
		return 0, 0, false
	}
	qtype := binary.BigEndian.Uint16(q[off : off+2])
	return off + 4, qtype, true
}

func appendA(resp, ip []byte) []byte {
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0, 1, 0, 1)
	resp = append(resp, 0, 0, 0, 60)
	resp = append(resp, 0, 4)
	return append(resp, ip...)
}

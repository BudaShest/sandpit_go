package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var (
	ntcbMagic = []byte{0x40, 0x4e, 0x54, 0x43} // @NTC
	// Ответ на *>S (IMEI): док — 404e544300000000010000000300455e2a3c53, msg *<S
	ackStarS = []byte{
		0x40, 0x4e, 0x54, 0x43, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
		0x45, 0x5e, 0x2a, 0x3c, 0x53,
	}
)

const (
	ntcbHeaderLen = 14
	maxPayload    = 4096
)

func main() {
	addr := ":5221"
	if p := os.Getenv("LISTEN_ADDR"); p != "" {
		addr = p
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("TCP dump listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	log.Printf("[%s] connected", remote)
	defer func() {
		_ = conn.Close()
		log.Printf("[%s] closed", remote)
	}()

	var acc []byte
	handshakeDone := false
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			fmt.Fprintf(os.Stdout, "\n--- [%s] %s (%d bytes) ---\n", ts, remote, n)
			os.Stdout.WriteString(hex.Dump(chunk))

			acc = append(acc, chunk...)
			if !handshakeDone {
				if tryHandshake(conn, remote, &acc) {
					handshakeDone = true
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] read: %v", remote, err)
			}
			return
		}
	}
}

// tryHandshake разбирает NTCB-кадры из acc: при первом payload с *>S шлёт *<S ack.
// Возвращает true, если ack успешно отправлен (дальше рукопожатие не повторяем).
func tryHandshake(conn net.Conn, remote string, acc *[]byte) bool {
	b := *acc
	i := 0
	for i+4 <= len(b) {
		if !bytes.Equal(b[i:i+4], ntcbMagic) {
			i++
			continue
		}
		if i+ntcbHeaderLen > len(b) {
			break
		}
		pl := int(binary.LittleEndian.Uint16(b[i+12 : i+14]))
		if pl < 0 || pl > maxPayload {
			i++
			continue
		}
		need := ntcbHeaderLen + pl
		if i+need > len(b) {
			break
		}
		payload := b[i+ntcbHeaderLen : i+need]
		if bytes.Contains(payload, []byte("*>S")) {
			if _, werr := conn.Write(ackStarS); werr != nil {
				log.Printf("[%s] write ack *<S: %v", remote, werr)
				*acc = b[i:]
				return false
			}
			log.Printf("[%s] sent NTCB ack (*<S) for *>S, %d bytes", remote, len(ackStarS))
			*acc = b[i+need:]
			return true
		}
		i += need
	}
	if i > 0 {
		*acc = b[i:]
	}
	return false
}

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
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

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			fmt.Fprintf(os.Stdout, "\n--- [%s] %s (%d bytes) ---\n", ts, remote, n)
			os.Stdout.WriteString(hex.Dump(buf[:n]))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] read: %v", remote, err)
			}
			return
		}
	}
}

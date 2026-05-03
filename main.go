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
	// Ответ на *>S (IMEI): док — 404e544300000000010000000300455e2a3c53
	ackStarS = []byte{
		0x40, 0x4e, 0x54, 0x43, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
		0x45, 0x5e, 0x2a, 0x3c, 0x53,
	}
	// Ответ на *>FLEX — hex из wiki Navtelecom (wire как есть).
	ackFlexWire []byte
)

func init() {
	const ackFlexHex = "404e544300000000010000000900b1a02a3c464c4558b01e1e"
	var err error
	ackFlexWire, err = hex.DecodeString(ackFlexHex)
	if err != nil {
		panic(err)
	}
}

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

type sess struct {
	starS bool
	flex  bool
	// allParamsLength — сумма байт выбранных полей FLEX 3.0 по маске (messages = msg_count * all_params_length).
	allParamsLength int
	// flexFieldIDs — порядок включённых полей по маске (для нарезки записи ~A).
	flexFieldIDs []int
}

func handleConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	log.Printf("[%s] connected", remote)
	defer func() {
		_ = conn.Close()
		log.Printf("[%s] closed", remote)
	}()

	var acc []byte
	var st sess
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			fmt.Fprintf(os.Stdout, "\n--- [%s] %s (%d bytes) ---\n", ts, remote, n)
			os.Stdout.WriteString(hex.Dump(chunk))

			acc = append(acc, chunk...)
			if !st.starS {
				tryStarSAck(conn, remote, &acc, &st)
			}
			if st.starS && !st.flex {
				tryFlexAck(conn, remote, &acc, &st)
			}
			if st.starS && st.flex {
				processFlexTelemetry(conn, remote, &acc, &st)
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

// tryStarSAck — первый кадр с *>S → ack *<S.
func tryStarSAck(conn net.Conn, remote string, acc *[]byte, st *sess) {
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
				return
			}
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			fmt.Fprintf(os.Stdout, "\n--- [%s] %s -> client, NTCB ack *<S (%d bytes) ---\n", ts, remote, len(ackStarS))
			os.Stdout.WriteString(hex.Dump(ackStarS))
			log.Printf("[%s] sent NTCB ack (*<S) for *>S, %d bytes", remote, len(ackStarS))
			st.starS = true
			*acc = b[i+need:]
			return
		}
		i += need
	}
	if i > 0 {
		*acc = b[i:]
	}
}

// tryFlexAck — кадр с *>FLEX: фиксируем маску, all_params_length, ack *<FLEX.
func tryFlexAck(conn net.Conn, remote string, acc *[]byte, st *sess) {
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
		if !bytes.Contains(payload, []byte(tagFLEX)) {
			i += need
			continue
		}
		proto, pVer, sVer, bfSize, mask, ok := parseFlexNegotiation(payload)
		if !ok {
			log.Printf("[%s] *>FLEX tag present but payload truncated or malformed, skipping frame", remote)
			i += need
			continue
		}
		ids := flexEnabledIDs(mask, int(bfSize))
		sum, unknown := sumFlexRecordLength(ids)
		log.Printf("[%s] *>FLEX: proto=0x%02x ver=0x%02x struct=0x%02x bitfield_size=%d mask_bytes=%d params=%v",
			remote, proto, pVer, sVer, bfSize, len(mask), ids)
		if len(unknown) > 0 {
			log.Printf("[%s] warning: no flex30FieldBytes for param IDs %v (all_params_length partial)", remote, unknown)
		}
		st.allParamsLength = sum
		st.flexFieldIDs = ids
		log.Printf("[%s] all_params_length=%d (sum of known field sizes)", remote, sum)

		out := ackFlexWire
		if _, werr := conn.Write(out); werr != nil {
			log.Printf("[%s] write ack *<FLEX: %v", remote, werr)
			*acc = b[i:]
			return
		}
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		fmt.Fprintf(os.Stdout, "\n--- [%s] %s -> client, NTCB ack *<FLEX (%d bytes) ---\n", ts, remote, len(out))
		os.Stdout.WriteString(hex.Dump(out))
		log.Printf("[%s] sent NTCB ack (*<FLEX), %d bytes", remote, len(out))
		st.flex = true
		*acc = b[i+need:]
		return
	}
	if i > 0 {
		*acc = b[i:]
	}
}

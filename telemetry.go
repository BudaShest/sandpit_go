package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// crc8Flex — Annex B (полином 0x31, init 0xFF).
func crc8Flex(data []byte) byte {
	crc := byte(0xFF)
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x31
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func buildAckFlexA(msgCount byte) []byte {
	prefix := []byte{0x7e, 0x41, msgCount}
	return append(prefix, crc8Flex(prefix))
}

// cutFlexPacketA ищет в начале data валидный ~A. hdr — 3 или 8 байт.
func cutFlexPacketA(data []byte, apl int) (total int, msgCount byte, records [][]byte, hdrLen int, ok bool) {
	if apl <= 0 || len(data) < 3 || data[0] != 0x7e || data[1] != 0x41 {
		return 0, 0, nil, 0, false
	}
	mc := data[2]
	if mc == 0 {
		return 0, 0, nil, 0, false
	}
	bodyLen := int(mc) * apl
	need3 := 3 + bodyLen + 1
	need8 := 8 + bodyLen + 1

	try := func(hlen, tot int) bool {
		if len(data) < tot {
			return false
		}
		pkt := data[:tot]
		if crc8Flex(pkt[:tot-1]) != pkt[tot-1] {
			return false
		}
		raw := pkt[hlen : tot-1]
		rec := make([][]byte, int(mc))
		for i := 0; i < int(mc); i++ {
			rec[i] = append([]byte(nil), raw[i*apl:(i+1)*apl]...)
		}
		total = tot
		msgCount = mc
		records = rec
		hdrLen = hlen
		ok = true
		return true
	}

	if len(data) >= need3 && try(3, need3) {
		return total, msgCount, records, hdrLen, true
	}
	if len(data) >= need8 && try(8, need8) {
		return total, msgCount, records, hdrLen, true
	}
	return 0, 0, nil, 0, false
}

func logParsedFlexA(remote string, msgCount byte, records [][]byte, fieldIDs []int) {
	log.Printf("[%s] ~A: msg_count=%d, records=%d, field_order=%v", remote, msgCount, len(records), fieldIDs)
	for ri, raw := range records {
		fmt.Fprintf(os.Stdout, "\n  --- [%s] MESSAGE_%d raw (%d bytes) ---\n", remote, ri+1, len(raw))
		os.Stdout.WriteString(hex.Dump(raw))
		off := 0
		for _, fid := range fieldIDs {
			if fid <= 0 || fid > 255 {
				continue
			}
			sz := int(flex30FieldBytes[fid])
			if sz == 0 {
				log.Printf("[%s] MESSAGE_%d: unknown field_%d at offset %d — stop", remote, ri+1, fid, off)
				break
			}
			if off+sz > len(raw) {
				log.Printf("[%s] MESSAGE_%d: truncated at field_%d", remote, ri+1, fid)
				break
			}
			chunk := raw[off : off+sz]
			log.Printf("[%s] MESSAGE_%d: field_%d (%d B) hex=%s", remote, ri+1, fid, sz, hex.EncodeToString(chunk))
			logFieldInterpretation(remote, ri+1, fid, chunk)
			off += sz
		}
		if off != len(raw) && off > 0 {
			log.Printf("[%s] MESSAGE_%d: consumed %d B, record %d B (apl/table mismatch?)", remote, ri+1, off, len(raw))
		}
	}
}

func logFieldInterpretation(remote string, msgIdx, fid int, chunk []byte) {
	switch fid {
	case 1:
		if len(chunk) == 4 {
			log.Printf("[%s] MESSAGE_%d: field_1 msg_number=%d", remote, msgIdx+1, binary.LittleEndian.Uint32(chunk))
		}
	case 2:
		if len(chunk) == 2 {
			log.Printf("[%s] MESSAGE_%d: field_2 event_code=%d", remote, msgIdx+1, binary.LittleEndian.Uint16(chunk))
		}
	case 3:
		if len(chunk) == 4 {
			log.Printf("[%s] MESSAGE_%d: field_3 time_unix_s=%d", remote, msgIdx+1, binary.LittleEndian.Uint32(chunk))
		}
	case 10, 11:
		if len(chunk) == 4 {
			log.Printf("[%s] MESSAGE_%d: field_%d i32=%d", remote, msgIdx+1, fid, int32(binary.LittleEndian.Uint32(chunk)))
		}
	}
}

func processFlexTelemetry(conn net.Conn, remote string, acc *[]byte, st *sess) {
	if st.allParamsLength <= 0 {
		return
	}
	b := *acc
	for len(b) > 0 {
		idx := bytes.Index(b, []byte{0x7e, 0x41})
		if idx < 0 {
			break
		}
		if idx > 0 {
			log.Printf("[%s] telemetry: drop %d byte(s) before ~A", remote, idx)
			b = b[idx:]
		}
		if len(b) < 3 {
			break
		}
		if b[2] == 0 {
			b = b[1:]
			continue
		}
		bodyLen := int(b[2]) * st.allParamsLength
		need3 := 3 + bodyLen + 1
		need8 := 8 + bodyLen + 1

		if len(b) < need3 {
			break
		}

		tot, mcOut, records, hdr, ok := cutFlexPacketA(b, st.allParamsLength)
		if !ok {
			if len(b) < need8 {
				break
			}
			log.Printf("[%s] ~A: CRC mismatch (apl=%d); skip 1 byte", remote, st.allParamsLength)
			b = b[1:]
			continue
		}
		log.Printf("[%s] ~A: ok hdr=%d total=%d B", remote, hdr, tot)
		logParsedFlexA(remote, mcOut, records, st.flexFieldIDs)
		ack := buildAckFlexA(mcOut)
		if _, werr := conn.Write(ack); werr != nil {
			log.Printf("[%s] write ~A ack: %v", remote, werr)
			*acc = b
			return
		}
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		fmt.Fprintf(os.Stdout, "\n--- [%s] %s -> client, FLEX ~A ack (%d bytes) ---\n", ts, remote, len(ack))
		os.Stdout.WriteString(hex.Dump(ack))
		log.Printf("[%s] sent ~A ack msg_count=%d", remote, mcOut)
		b = b[tot:]
	}
	*acc = b
}

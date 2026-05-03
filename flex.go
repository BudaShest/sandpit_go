package main

import "bytes"

// Размеры полей записи FLEX 3.0 по номеру параметра (Annex A.1, NTCB v6.2).
// 0 — неизвестно (нужно дополнить по доке при появлении ID в маске).
var flex30FieldBytes = [256]uint16{
	1: 4, 2: 2, 3: 4, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1,
	9: 4, 10: 4, 11: 4, 12: 4, 13: 4, 14: 2, 15: 4,
	16: 4, 17: 2, 18: 2, 19: 2, 20: 2, 21: 2, 22: 2, 23: 2, 24: 2,
	25: 2, 26: 2, 27: 2, 28: 2, 29: 1, 30: 1, 31: 1, 32: 1,
	33: 4, 34: 4, 35: 2, 36: 2, 37: 4, 38: 2, 39: 2, 40: 2, 41: 2, 42: 2, 43: 2, 44: 2,
	45: 1, 46: 1, 47: 1, 48: 1, 49: 1, 50: 1, 51: 1, 52: 1,
	53: 2, 54: 4, 55: 2, 56: 1, 57: 4, 58: 2, 59: 2, 60: 2, 61: 2, 62: 2,
	63: 1, 64: 1, 65: 1, 66: 2, 67: 4, 68: 2, 69: 1,
	70: 8,
	71: 2, 72: 1, 73: 16, 74: 4, 75: 2, 76: 4, 77: 37,
	78: 1, 79: 1, 80: 1, 81: 1, 82: 1, 83: 1,
	84: 3, 85: 3, 86: 3, 87: 3, 88: 3, 89: 3, 90: 3, 91: 3, 92: 3, 93: 3,
	94: 6, 95: 12,
	101: 1, 102: 4, 103: 4, 104: 1, 105: 4, 106: 2,
	107: 6, 108: 2, 109: 6,
	118: 1, 119: 2, 120: 2, 121: 2, 122: 1,
	123: 1, 124: 1, 125: 1,
	126: 1, 127: 4,
	139: 1,
	200: 2,
	206: 4,
	238: 4, 239: 4,
}

const tagFLEX = "*>FLEX"

// parseFlexNegotiation ищет *>FLEX в payload кадра NTCB и возвращает метаданные и сырую маску.
func parseFlexNegotiation(payload []byte) (proto, protoVer, structVer, bitfieldSize byte, mask []byte, ok bool) {
	i := bytes.Index(payload, []byte(tagFLEX))
	if i < 0 {
		return 0, 0, 0, 0, nil, false
	}
	rest := payload[i+len(tagFLEX):]
	if len(rest) < 4 {
		return 0, 0, 0, 0, nil, false
	}
	proto, protoVer, structVer, bitfieldSize = rest[0], rest[1], rest[2], rest[3]
	mask = rest[4:]
	return proto, protoVer, structVer, bitfieldSize, mask, true
}

// flexEnabledIDs возвращает номера включённых полей (1..bitfieldSize). Биты: поле 1 — MSB байта 0 (Annex A.1).
func flexEnabledIDs(mask []byte, bitfieldSize int) []int {
	if bitfieldSize <= 0 || bitfieldSize > 255 {
		return nil
	}
	var ids []int
	for k := 1; k <= bitfieldSize; k++ {
		bi := k - 1 // индекс бита с нуля
		if bi/8 >= len(mask) {
			break
		}
		bitInByte := 7 - (bi % 8)
		if mask[bi/8]&(1<<bitInByte) != 0 {
			ids = append(ids, k)
		}
	}
	return ids
}

func sumFlexRecordLength(ids []int) (sum int, unknown []int) {
	for _, id := range ids {
		if id <= 0 || id > 255 {
			continue
		}
		sz := flex30FieldBytes[id]
		if sz == 0 {
			unknown = append(unknown, id)
			continue
		}
		sum += int(sz)
	}
	return sum, unknown
}

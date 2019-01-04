package addr

import (
	"strings"
	"errors"
	"crypto/sha256"
	"encoding/hex"
)

const (
	ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	EXPAND_PREFIX = []int{2, 9, 20, 3, 15, 9, 14, 3, 1, 19, 8, 0}
	EXPAND_PREFIX_TESTNET = []int{2, 3, 8, 20, 5, 19, 20, 0}
	BASE16MAP = map[string]int{
		"0":0,	"1":1,	"2":2,	"3":3,	"4":4,
		"5":5,	"6":6,	"7":7,	"8":8,	"9":9,
		"a":10, "b":11, "c":12, "d":13, "e":14,
		"f":15,
	}
	ALPHABET_MAP = map[string]int{
		"1":0,	"2":1,	"3":2,	"4":3,	"5":4,	"6":5,	"7":6,	"8":7,
		"9":8,	"A":9,	"B":10,	"C":11,	"D":12,	"E":13,	"F":14,	"G":15,
		"H":16,	"J":17,	"K":18,	"L":19,	"M":20,	"N":21,	"P":22,	"Q":23,
		"R":24,	"S":25,	"T":26,	"U":27,	"V":28,	"W":29,	"X":30,	"Y":31,
		"Z":32,	"a":33, "b":34,	"c":35,	"d":36,	"e":37,	"f":38,	"g":39,
		"h":40,	"i":41,	"j":42,	"k":43,	"m":44,	"n":45,	"o":46,	"p":47,
		"q":48,	"r":49,	"s":50,	"t":51,	"u":52,	"v":53,	"w":54,	"x":55,
		"y":56,	"z":57}
	BECH_ALPHABET = map[string]int{
		"q":0,	"p":1,	"z":2,	"r":3,	"y":4,	"9":5,	"x":6,	"8":7,
		"g":8,	"f":9,	"2":10,	"t":11,	"v":12,	"d":13,	"w":14,	"0":15,
		"s":16,	"3":17,	"j":18,	"n":19,	"5":20,	"4":21,	"k":22,	"h":23,
		"c":24,	"e":25,	"6":26,	"m":27,	"u":28,	"a":29,	"7":30,	"l":31,
	}
)


//bch cash Addr convert to btc old addr
func BitcoinCashAddrToBtcOldAddr(bchNewAddr string, isTestNet bool) (btcOldAddr string, err error) {
	values, err := decodeNewAddr(bchNewAddr, isTestNet)
	if err != nil {
		return
	}

	values, err = convertBits(values[:len(values)-8], 5, 8, false)
	if err != nil {
		return
	}
	addressType := values[0] >> 3
	tmpLen := 21
	if tmpLen+1 > len(values) {
		tmpLen = len(values) - 1
	}
	addressHash := values[1 : tmpLen+1]

	var bytes []byte
	if isTestNet {
		if addressType != 0 {
			bytes = []byte{0xc4}
		} else {
			bytes = []byte{0x6f}
		}
	} else {
		if addressType != 0 {
			bytes = []byte{0x05}
		} else {
			bytes = []byte{0x00}
		}
	}
	for _, v := range addressHash {
		bytes = append(bytes, byte(v))
	}
	merged := append(bytes, doubleSha256ByteArray(bytes)...)
	digits := []byte{0}
	for i := 0; i < len(merged); i++ {
		carry := int(merged[i])
		for j := 0; j < len(digits); j++ {
			carry += (int(digits[j]) << 8)
			digits[j] = byte(carry % 58)
			carry = int(carry / 58)
		}

		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry = int(carry / 58)
		}
	}

	for i := 0; i < len(merged) && merged[i] == 0; i++ {
		digits = append(digits, 0)
	}

	converted := make([]byte, 0, len(digits))
	for i := len(digits) - 1; i >= 0; i-- {
		if int(digits[i]) > len(ALPHABET) {
			err = errors.New("invalid character!")
			return
		}
		converted = append(converted, ALPHABET[digits[i]])
	}

	btcOldAddr = string(converted)
	return
}

func decodeNewAddr(bchNewAddr string, isTestNet bool) (data []int, err error) {
	inputNew := strings.ToLower(bchNewAddr)

	var affterPrefix int
	var dataArr []int
	if strings.IndexAny(inputNew, ":") < 0 {
		err = errors.New("address without valid prefix")
		return
	} else if inputNew[:12] == "bitcoincash:" {
		if isTestNet {
			err = errors.New("net mode and address value isn't match")
			return
		}
		affterPrefix = 12
		dataArr = append(dataArr, EXPAND_PREFIX...)
	} else if inputNew[:8] == "bchtest:" {
		if !isTestNet {
			err = errors.New("net mode and address value isn't match")
			return
		}
		affterPrefix = 8
		dataArr = append(dataArr, EXPAND_PREFIX_TESTNET...)
	} else {
		err = errors.New("unknown address type")
		return
	}

	var tmpValues []int
	for tmpValues = make([]int, 0, len(inputNew)); affterPrefix < len(inputNew); affterPrefix++ {
		indexValue := inputNew[affterPrefix : affterPrefix+1]
		if v, ok := BECH_ALPHABET[indexValue]; ok {
			tmpValues = append(tmpValues, v)
		} else {
			err = errors.New("Unexpected character in address!")
			return
		}
	}

	dataArr = append(dataArr, tmpValues...)
	if checksum := polyMod(dataArr); checksum != 0 {
		err = errors.New("checksum value is wrong!")
		return
	}

	data = tmpValues
	return
}

func polyMod(data []int) int {
	c := 1
	for i := 0; i < len(data); i++ {
		c0 := c >> 35
		c = ((c & 0x07ffffffff) << 5) ^ data[i]
		if (c0 & 1) != 0 {
			c ^= 0x98f2bc8e61
		}
		if (c0 & 2) != 0 {
			c ^= 0x79b76d99e2
		}
		if (c0 & 4) != 0 {
			c ^= 0xf33e5fb3c4
		}
		if (c0 & 8) != 0 {
			c ^= 0xae2eabe2a8
		}
		if (c0 & 16) != 0 {
			c ^= 0x1e4f43e470
		}
	}
	return c ^ 1
}

func convertBits(data []int, fromBits, toBits int, pad bool) (ret []int, err error) {
	var acc, bits int
	ret = make([]int, 0, len(data))
	maxv := (1 << uint(toBits)) - 1
	maxacc := (1 << uint(fromBits+toBits-1)) - 1

	for i := 0; i < len(data); i++ {
		value := data[i]

		if value < 0 || (value>>uint(fromBits)) != 0 {
			err = errors.New("address error")
			return
		}

		acc = (acc<<uint(fromBits) | value) & maxacc
		bits += fromBits

		for bits >= toBits {
			bits -= toBits
			ret = append(ret, ((acc >> uint(bits)) & maxv))
		}
	}

	if pad {
		if bits != 0 {
			tmpval := (acc << uint(toBits-bits)) & maxv
			ret = append(ret, tmpval)
		}
	} else if (bits >= fromBits) || ((acc<<uint(toBits-bits))&maxv) != 0 {
		err = errors.New("address error")
		return
	}

	return
}

func doubleSha256ByteArray(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	hash := hex.EncodeToString(h.Sum(nil))
	hashArr := make([]byte, 0, len(bytes))
	for i := 0; i < 32; i++ {
		tmpv := BASE16MAP[string(hash[2*i])]*16 + BASE16MAP[string(hash[2*i+1])]
		hashArr = append(hashArr, byte(tmpv))
	}

	h = sha256.New()
	h.Write(hashArr)
	hash = hex.EncodeToString(h.Sum(nil))
	hashArr = make([]byte, 0, len(bytes))
	for i := 0; i < 4; i++ {
		tmpv := BASE16MAP[string(hash[2*i])]*16 + BASE16MAP[string(hash[2*i+1])]
		hashArr = append(hashArr, byte(tmpv))
	}
	return hashArr
}

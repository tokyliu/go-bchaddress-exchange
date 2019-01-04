package addr

import (
	"testing"
)

func TestBitcoinCashAddrToBtcOldAddr(t *testing.T) {
	btcaddr, err := BitcoinCashAddrToBtcOldAddr("bchtest:qzllrrsyph8e3k5mteevzpzz2vd6r4kl95dj0uty04", true)
	if err != nil || btcaddr != "my1rjDEvRCufsu3HhfAQFb7rqi5BW4Qq5e" {
		t.Error( btcaddr, "!=my1rjDEvRCufsu3HhfAQFb7rqi5BW4Qq5e")
	}
	btcaddr, err = BitcoinCashAddrToBtcOldAddr("qzllrrsyph8e3k5mteevzpzz2vd6r4kl95dj0uty04", true)
	if err == nil {
		t.Error("qzllrrsyph8e3k5mteevzpzz2vd6r4kl95dj0uty04 without valid prefix")
	}
	btcaddr, err = BitcoinCashAddrToBtcOldAddr("bitcoincash:qrx0d0uf4jhm3au29x6975qhmxcp74luw5sjyhe4r9", false)
	if err != nil || btcaddr != "1KgkSVv2GVb8qEmV7GsuprRAUb9EXpDiDs" {
		t.Error( btcaddr, "!=1KgkSVv2GVb8qEmV7GsuprRAUb9EXpDiDs")
	}
	btcaddr, err = BitcoinCashAddrToBtcOldAddr("qrx0d0uf4jhm3au29x6975qhmxcp74luw5sjyhe4r9", false)
	if err == nil {
		t.Error("qrx0d0uf4jhm3au29x6975qhmxcp74luw5sjyhe4r9 without valid prefix")
	}
}


package internal

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func Fingerprint(data []byte) [16]byte {
	return md5.Sum(data)
}

func NewKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	return key
}

package adicrypto

import (
	"crypto"
	"crypto/sha256"
)

type cSHA256Hasher struct{}

func (hasher *cSHA256Hasher) Hash(payload []byte) (res []byte, err error) {
	hashed := sha256.Sum256(payload)
	return hashed[:], nil
}

func (hasher *cSHA256Hasher) Type() crypto.Hash {
	return crypto.SHA256
}

func create256Hasher() (hasher IHasher, err error) {
	return new(cSHA256Hasher), nil
}

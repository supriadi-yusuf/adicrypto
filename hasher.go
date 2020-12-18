package adicrypto

import (
	"crypto"
	"errors"
)

// THasher is type of hasher (data type)
type THasher int

const (

	// SHA256HasherType is value for SHA256Hasher type
	SHA256HasherType THasher = iota
)

// IHasher is interface for hashing
type IHasher interface {
	Hash(payload []byte) (res []byte, err error)
	Type() crypto.Hash
}

// IHasherFactory is interface to create hasher
type IHasherFactory interface {
	CreateHasher(hasherType THasher) (hasher IHasher, err error)
}

type cHasherFactory struct{}

func (factory *cHasherFactory) CreateHasher(hasherType THasher) (hasher IHasher, err error) {
	switch hasherType {
	case SHA256HasherType:
		return create256Hasher()
	default:
		return nil, errors.New("unknown hasher type")
	}
}

// CreateHasherFactory is function to create hasher factory
func CreateHasherFactory() (factory IHasherFactory) {
	return new(cHasherFactory)
}

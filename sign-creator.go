package adicrypto

import (
	"crypto/rsa"
	"errors"
)

// TSignCreator is type of signature creator (data type)
type TSignCreator int

const (

	// RSASignCreatorType is value for RSASignatureCreator type
	RSASignCreatorType TSignCreator = iota
)

// ISignCreator is interface to generate signature
type ISignCreator interface {
	GenerateSignature(payload []byte) (signature []byte, err error)
	SetKey(key *rsa.PrivateKey)
	SetHasher(hasher IHasher)
}

// ISignCreatorFactory is interface to create SignatureCreator
type ISignCreatorFactory interface {
	CreateSignCreator(creatorType TSignCreator) (creator ISignCreator, err error)
}

type cSignCreatorFactory struct{}

func (factory *cSignCreatorFactory) CreateSignCreator(creatorType TSignCreator) (creator ISignCreator, err error) {
	switch creatorType {
	case RSASignCreatorType:
		return createRsaSignCreator()
	default:
		return nil, errors.New("unknown type of creator")
	}
}

// CreateSignCreatorFactory is factory to create sign creator
func CreateSignCreatorFactory() (factory ISignCreatorFactory) {
	return new(cSignCreatorFactory)
}

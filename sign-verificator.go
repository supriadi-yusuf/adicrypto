package adicrypto

import (
	"crypto/rsa"
	"errors"
)

// TSignVerificator is type of signature verificator (data type)
type TSignVerificator int

const (
	// RSASignVerificator is value for RSA sign verificator type
	RSASignVerificator TSignVerificator = iota
)

// ISignVerificator is interface to verify signature
type ISignVerificator interface {
	VerifySignature(payload []byte, signature []byte) (valid bool, err error)
	SetKey(key *rsa.PublicKey)
	SetHasher(hasher IHasher)
}

// ISignVerificatorFactory is interface to create sign verificator
type ISignVerificatorFactory interface {
	CreateSignVerificator(verificatorType TSignVerificator) (verificator ISignVerificator, err error)
}

type cSignVerificatorFactory struct{}

func (factory *cSignVerificatorFactory) CreateSignVerificator(verificatorType TSignVerificator) (verificator ISignVerificator, err error) {

	switch verificatorType {
	case RSASignVerificator:
		return createRSASignVerificator()
	default:
		return nil, errors.New("unknown type of verificator")
	}

}

// CreateSignVerificatorFactory is function to create sign verificator factory
func CreateSignVerificatorFactory() (factory ISignVerificatorFactory) {
	return new(cSignVerificatorFactory)
}

package adicrypto

import (
	"crypto/rand"
	"crypto/rsa"
)

type cRSASignCreator struct {
	privateKey *rsa.PrivateKey
	hasher     IHasher
}

func (sg *cRSASignCreator) GenerateSignature(payload []byte) (signature []byte, err error) {

	hashed, err := sg.hasher.Hash(payload)
	if err != nil {
		return nil, err
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, sg.privateKey, sg.hasher.Type(), hashed)
	if err != nil {
		return nil, err
	}

	return signatureBytes, nil
}

func (sg *cRSASignCreator) SetKey(key *rsa.PrivateKey) {
	sg.privateKey = key
}

func (sg *cRSASignCreator) SetHasher(hasher IHasher) {
	sg.hasher = hasher
}

func createRsaSignCreator() (creator ISignCreator, err error) {
	return new(cRSASignCreator), nil
}

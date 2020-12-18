package adicrypto

import "crypto/rsa"

type cRSASignVerificator struct {
	publicKey *rsa.PublicKey
	hasher    IHasher
}

func (sg *cRSASignVerificator) VerifySignature(payload []byte, signature []byte) (valid bool, err error) {

	hashed, err := sg.hasher.Hash(payload)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(sg.publicKey, sg.hasher.Type(), hashed, signature)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (sg *cRSASignVerificator) SetKey(key *rsa.PublicKey) {
	sg.publicKey = key
}

func (sg *cRSASignVerificator) SetHasher(hasher IHasher) {
	sg.hasher = hasher
}

func createRSASignVerificator() (verificator ISignVerificator, err error) {
	return new(cRSASignVerificator), nil
}

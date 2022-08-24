package adicrypto

import "crypto/rand"

func Random(length int) ([]byte, error) {
	randBytes := make([]byte, length)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	return randBytes, nil
}

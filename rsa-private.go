package adicrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

// PrivateKeyToBytes is function to converts rsa private key into bytes data
func PrivateKeyToBytes(privateKey *rsa.PrivateKey) (keyBytes []byte, err error) {
	return x509.MarshalPKCS1PrivateKey(privateKey), nil
}

// LoadPrivateKey is function to load private key into RAM
func LoadPrivateKey(privateKey *rsa.PrivateKey, privateKeyMem []byte) (err error) {
	keyBytes, err := PrivateKeyToBytes(privateKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	prKeyBytes := pem.EncodeToMemory(block)
	privateKeyMem = append(privateKeyMem, prKeyBytes...)

	return nil
}

// SavePrivateKey is function to rsa private key to file
func SavePrivateKey(privateKey *rsa.PrivateKey, fileName string) (err error) {

	prKeyBytes := make([]byte, 0)
	err = LoadPrivateKey(privateKey, prKeyBytes)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fileName, prKeyBytes, os.ModePerm)

	return
}

// BytesToPrivateKey is function converting bytes data to rsa private key
func BytesToPrivateKey(keyBytes []byte) (privateKey *rsa.PrivateKey, err error) {
	return x509.ParsePKCS1PrivateKey(keyBytes)
}

// PEMBytesToKeyBytes is function converting pem bytes into key bytes
func PEMBytesToKeyBytes(pemBytes []byte) (keyBytes []byte, err error) {
	block, _ := pem.Decode(pemBytes)
	if x509.IsEncryptedPEMBlock(block) {

		keyBytes, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	} else {
		keyBytes = block.Bytes
	}

	return keyBytes, nil
}

// PEMBytesToPrivateKey is function converting pem bytes to private key
func PEMBytesToPrivateKey(pemBytes []byte) (privateKey *rsa.PrivateKey, err error) {

	keyBytes, err := PEMBytesToKeyBytes(pemBytes)
	if err != nil {
		return nil, err
	}

	return BytesToPrivateKey(keyBytes)
}

// CreatePrivateKeyFromFile is function generating private key based on data in file content
func CreatePrivateKeyFromFile(fileName string) (privateKey *rsa.PrivateKey, err error) {

	pemBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	privateKey, err = PEMBytesToPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return
}

// func DecryptPKCS1v15(rand io.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error)

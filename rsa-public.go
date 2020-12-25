package adicrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// PublicKeyToBytes is function to convert rsa public key to bytes
func PublicKeyToBytes(publicKey *rsa.PublicKey) (keyBytes []byte, err error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// LoadPublicKey is function to load public key into RAM
func LoadPublicKey(publicKey *rsa.PublicKey, publicKeyMem []byte) (err error) {
	keyBytes, err := PublicKeyToBytes(publicKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: keyBytes,
	}

	pbKeyBytes := pem.EncodeToMemory(block)
	publicKeyMem = append(publicKeyMem, pbKeyBytes...)

	return nil
}

// SavePublicKey is function to rsa public key to file
func SavePublicKey(publicKey *rsa.PublicKey, fileName string) (err error) {

	pbKeyBytes := make([]byte, 0)
	err = LoadPublicKey(publicKey, pbKeyBytes)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fileName, pbKeyBytes, os.ModePerm)

	return
}

// BytesToPublicKey is function converting bytes data to rsa public key
func BytesToPublicKey(keyBytes []byte) (publicKey *rsa.PublicKey, err error) {

	ifc, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}

	var ok bool

	publicKey, ok = ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("assertion to rsa public key is error")
	}

	return publicKey, nil
}

// PEMBytesToPublicKey is function converting pem bytes to public key
func PEMBytesToPublicKey(pemBytes []byte) (publicKey *rsa.PublicKey, err error) {

	keyBytes, err := PEMBytesToKeyBytes(pemBytes)
	if err != nil {
		return nil, err
	}

	return BytesToPublicKey(keyBytes)
}

// CreatePublicKeyFromFile is function generating public key based on data in file content
func CreatePublicKeyFromFile(fileName string) (publicKey *rsa.PublicKey, err error) {

	pemBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	publicKey, err = PEMBytesToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return
}

// func EncryptPKCS1v15(rand io.Reader, pub *PublicKey, msg []byte) ([]byte, error)

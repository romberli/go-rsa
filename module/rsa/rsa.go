package rsa

import (
	"fmt"

	"github.com/romberli/go-util/constant"
	"github.com/romberli/go-util/crypto"
)

const (
	defaultEncryptTemplate = `{"private_key": "%s", "public_key": "%s", "message": "%s", "cipher": "%s"}`
)

// Encrypt encrypts the message
func Encrypt(message string) (string, error) {
	r, err := crypto.NewRSA()
	if err != nil {
		return constant.EmptyString, err
	}

	cipher, err := r.Encrypt(message)
	if err != nil {
		return constant.EmptyString, err
	}

	privateKey, err := r.GetPrivateKey()
	if err != nil {
		return constant.EmptyString, err
	}
	publicKey, err := r.GetPublicKey()
	if err != nil {
		return constant.EmptyString, err
	}

	return fmt.Sprintf(defaultEncryptTemplate, privateKey, publicKey, message, cipher), nil
}

// EncryptWithPublicKeyString encrypts the message with public key string
func EncryptWithPublicKeyString(publicKey, message string) (string, error) {
	cipher, err := crypto.EncryptWithPublicKeyString(publicKey, message)
	if err != nil {
		return constant.EmptyString, err
	}

	return fmt.Sprintf(defaultEncryptTemplate, constant.EmptyString, publicKey, message, cipher), nil
}

// DecryptWithPublicKeyString decrypts the cipher with public key string
func DecryptWithPublicKeyString(publicKey, cipher string) (string, error) {
	message, err := crypto.DecryptWithPublicKeyString(publicKey, cipher)
	if err != nil {
		return constant.EmptyString, err
	}

	return fmt.Sprintf(defaultEncryptTemplate, constant.EmptyString, publicKey, message, cipher), nil
}

// EncryptWithPrivateKeyString encrypts the message with private key string
func EncryptWithPrivateKeyString(privateKey, message string) (string, error) {
	r, err := crypto.NewRSAWithPrivateKeyString(privateKey)
	if err != nil {
		return constant.EmptyString, err
	}

	cipher, err := r.EncryptWithPrivateKey(message)
	if err != nil {
		return constant.EmptyString, err
	}

	publicKey, err := r.GetPublicKey()
	if err != nil {
		return constant.EmptyString, err
	}

	return fmt.Sprintf(defaultEncryptTemplate, privateKey, publicKey, message, cipher), nil
}

// DecryptWithPrivateKeyString decrypts the cipher with private key string
func DecryptWithPrivateKeyString(privateKey, cipher string) (string, error) {
	r, err := crypto.NewRSAWithPrivateKeyString(privateKey)
	if err != nil {
		return constant.EmptyString, err
	}

	message, err := r.DecryptWithPrivateKey(cipher)
	if err != nil {
		return constant.EmptyString, err
	}

	publicKey, err := r.GetPublicKey()
	if err != nil {
		return constant.EmptyString, err
	}

	return fmt.Sprintf(defaultEncryptTemplate, privateKey, publicKey, message, cipher), nil
}

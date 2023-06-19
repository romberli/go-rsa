package rsa

import (
	"fmt"

	"github.com/romberli/go-util/constant"
	"github.com/romberli/go-util/crypto"

	pkgMessage "github.com/romberli/go-rsa/pkg/message"
	"github.com/romberli/go-rsa/pkg/util"

	rsaMessage "github.com/romberli/go-rsa/pkg/message/rsa"
)

const (
	publicKeyType  = "public"
	privateKeyType = "private"

	defaultEncryptTemplate = `{"encrypt_key_type": "%s", "private_key": "%s", "public_key": "%s", "message": "%s", "cipher": "%s"}`
	defaultDecryptTemplate = `{"decrypt_key_type": "%s", "private_key": "%s", "public_key": "%s", "message": "%s", "cipher": "%s"}`
)

// Encrypt encrypts the message
func Encrypt(keyType, message string) (string, error) {
	r, err := crypto.NewRSA()
	if err != nil {
		return constant.EmptyString, err
	}

	var cipher string

	switch keyType {
	case publicKeyType:
		cipher, err = r.Encrypt(message)
		if err != nil {
			return constant.EmptyString, err
		}
	case privateKeyType:
		cipher, err = r.EncryptWithPrivateKey(message)
		if err != nil {
			return constant.EmptyString, err
		}
	default:
		return constant.EmptyString, pkgMessage.NewMessage(rsaMessage.ErrRSANotValidKeyType, keyType)
	}

	privateKey, err := r.GetPrivateKey()
	if err != nil {
		return constant.EmptyString, err
	}
	publicKey, err := r.GetPublicKey()
	if err != nil {
		return constant.EmptyString, err
	}

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, keyType, privateKey, publicKey, message, cipher))
}

// EncryptWithPublicKeyString encrypts the message with public key string
func EncryptWithPublicKeyString(publicKey, message string) (string, error) {
	cipher, err := crypto.EncryptWithPublicKeyString(publicKey, message)
	if err != nil {
		return constant.EmptyString, err
	}

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, publicKeyType, constant.EmptyString, publicKey, message, cipher))
}

// DecryptWithPublicKeyString decrypts the cipher with public key string
func DecryptWithPublicKeyString(publicKey, cipher string) (string, error) {
	message, err := crypto.DecryptWithPublicKeyString(publicKey, cipher)
	if err != nil {
		return constant.EmptyString, err
	}

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, publicKeyType, constant.EmptyString, publicKey, message, cipher))
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

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, privateKeyType, privateKey, publicKey, message, cipher))
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

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, privateKeyType, privateKey, publicKey, message, cipher))
}

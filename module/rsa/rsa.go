package rsa

import (
	"fmt"

	"github.com/romberli/go-util/constant"
	"github.com/romberli/go-util/crypto"

	"github.com/romberli/go-rsa/config"
	pkgMessage "github.com/romberli/go-rsa/pkg/message"
	"github.com/romberli/go-rsa/pkg/util"

	msgRSA "github.com/romberli/go-rsa/pkg/message/rsa"
)

const (
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
	case config.DefaultRSAPrivate:
		cipher, err = r.Encrypt(message)
		if err != nil {
			return constant.EmptyString, err
		}
	case config.DefaultRSAPublic:
		cipher, err = r.EncryptWithPrivateKey(message)
		if err != nil {
			return constant.EmptyString, err
		}
	default:
		return constant.EmptyString, pkgMessage.NewMessage(msgRSA.ErrRSANotValidKeyType, keyType)
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

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, config.DefaultRSAPrivate, privateKey, publicKey, message, cipher))
}

// EncryptWithPublicKeyString encrypts the message with public key string
func EncryptWithPublicKeyString(publicKey, message string) (string, error) {
	cipher, err := crypto.EncryptWithPublicKeyString(publicKey, message)
	if err != nil {
		return constant.EmptyString, err
	}

	return util.PrettyJSONString(fmt.Sprintf(defaultEncryptTemplate, config.DefaultRSAPublic, constant.EmptyString, publicKey, message, cipher))
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

	return util.PrettyJSONString(fmt.Sprintf(defaultDecryptTemplate, config.DefaultRSAPrivate, privateKey, publicKey, message, cipher))
}

// DecryptWithPublicKeyString decrypts the cipher with public key string
func DecryptWithPublicKeyString(publicKey, cipher string) (string, error) {
	message, err := crypto.DecryptWithPublicKeyString(publicKey, cipher)
	if err != nil {
		return constant.EmptyString, err
	}

	return util.PrettyJSONString(fmt.Sprintf(defaultDecryptTemplate, config.DefaultRSAPublic, constant.EmptyString, publicKey, message, cipher))
}

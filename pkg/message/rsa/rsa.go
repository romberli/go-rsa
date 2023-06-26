package rsa

import (
	"github.com/romberli/go-util/config"

	"github.com/romberli/go-rsa/pkg/message"
)

func init() {
	initRSADebugMessage()
	initRSAInfoMessage()
	initRSAErrorMessage()
}

const (
	// debug

	// info

	// error
	ErrRSANotValidKeyType = 401001
	ErrRSAEncrypt         = 401002
	ErrRSADecrypt         = 401003
)

func initRSADebugMessage() {

}

func initRSAInfoMessage() {

}

func initRSAErrorMessage() {
	message.Messages[ErrRSANotValidKeyType] = config.NewErrMessage(message.DefaultMessageHeader, ErrRSANotValidKeyType,
		"rsa: key type must be either public or private, %s is not valid")
	message.Messages[ErrRSAEncrypt] = config.NewErrMessage(message.DefaultMessageHeader, ErrRSAEncrypt,
		"rsa: encrypt failed. encrypt: %s, key: %s, input: %s")
	message.Messages[ErrRSADecrypt] = config.NewErrMessage(message.DefaultMessageHeader, ErrRSADecrypt,
		"rsa: decrypt failed. decrypt: %s, key: %s, input: %s")
}

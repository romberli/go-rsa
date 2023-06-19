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
	ErrRSAEmptyKeyString  = 401002
	ErrRSAEncrypt         = 401003
)

func initRSADebugMessage() {

}

func initRSAInfoMessage() {

}

func initRSAErrorMessage() {
	message.Messages[ErrRSANotValidKeyType] = config.NewErrMessage(message.DefaultMessageHeader, ErrRSANotValidKeyType,
		"rsa: key type must be either public or private, %s is not valid")
	message.Messages[ErrRSAEmptyKeyString] = config.NewErrMessage(message.DefaultMessageHeader, ErrRSAEmptyKeyString,
		"rsa: key string is empty")
	message.Messages[ErrRSAEncrypt] = config.NewErrMessage(message.DefaultMessageHeader, ErrRSAEncrypt,
		"rsa: encrypt failed. keyType: %s, keyString: %s, input: %s")
}

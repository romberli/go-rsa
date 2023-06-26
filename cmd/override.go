package cmd

import (
	"strings"

	"github.com/romberli/go-util/constant"
	"github.com/spf13/viper"

	"github.com/romberli/go-rsa/config"
	"github.com/romberli/go-rsa/pkg/message"
)

// OverrideConfigByCLI read configuration from command line interface, it will override the config file configuration
func OverrideConfigByCLI() error {
	// override log
	err := overrideLogByCLI()
	if err != nil {
		return err
	}

	// override rsa
	overrideRSAByCLI()

	// validate configuration
	err = config.ValidateConfig()
	if err != nil {
		return message.NewMessage(message.ErrValidateConfig, err)
	}

	return nil
}

// overrideLogByCLI overrides the log section by command line interface
func overrideLogByCLI() error {
	// log.level
	if logLevel != constant.DefaultRandomString {
		logLevel = strings.ToLower(logLevel)
		viper.Set(config.LogLevelKey, logLevel)
	}
	// log.format
	if logFormat != constant.DefaultRandomString {
		logLevel = strings.ToLower(logFormat)
		viper.Set(config.LogFormatKey, logFormat)
	}

	return nil
}

// overrideRSAByCLI overrides the rsa section by command line interface
func overrideRSAByCLI() {
	// rsa.encrypt
	if rsaEncrypt != constant.DefaultRandomString {
		viper.Set(config.RSAEncryptKey, rsaEncrypt)
	}
	// rsa.decrypt
	if rsaDecrypt != constant.DefaultRandomString {
		viper.Set(config.RSADecryptKey, rsaDecrypt)
	}
	// rsa.private
	if rsaPrivate != constant.DefaultRandomString {
		viper.Set(config.RSAPrivateKey, rsaPrivate)
	}
	// rsa.public
	if rsaPublic != constant.DefaultRandomString {
		viper.Set(config.RSAPublicKey, rsaPublic)
	}
	// input
	if input != constant.DefaultRandomString {
		viper.Set(config.InputKey, input)
	}
}

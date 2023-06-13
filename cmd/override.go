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
	// validate configuration
	err = config.ValidateConfig()
	if err != nil {
		return message.NewMessage(message.ErrValidateConfig, err)
	}

	return nil
}

// overrideLogByCLI overrides the log section by command line interface
func overrideLogByCLI() error {
	if logLevel != constant.DefaultRandomString {
		logLevel = strings.ToLower(logLevel)
		viper.Set(config.LogLevelKey, logLevel)
	}
	if logFormat != constant.DefaultRandomString {
		logLevel = strings.ToLower(logFormat)
		viper.Set(config.LogFormatKey, logFormat)
	}

	return nil
}

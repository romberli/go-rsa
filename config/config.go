/*
Copyright © 2020 Romber Li <romber2001@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"strings"

	"github.com/pingcap/errors"
	"github.com/romberli/go-multierror"
	"github.com/romberli/go-util/common"
	"github.com/romberli/go-util/constant"
	"github.com/romberli/log"
	"github.com/spf13/cast"
	"github.com/spf13/viper"

	"github.com/romberli/go-rsa/pkg/message"

	msgRSA "github.com/romberli/go-rsa/pkg/message/rsa"
)

var (
	ValidLogLevels  = []string{"debug", "info", "warn", "warning", "error", "fatal"}
	ValidLogFormats = []string{"text", "json"}
	ValidKeyTypes   = []string{"public", "private"}
)

// SetDefaultConfig set default configuration, it is the lowest priority
func SetDefaultConfig(baseDir string) {
	// log
	viper.SetDefault(LogLevelKey, log.DefaultLogLevel)
	viper.SetDefault(LogFormatKey, log.DefaultLogFormat)
	// rsa
	viper.SetDefault(RSAEncryptKey, DefaultRSAPrivate)
	viper.SetDefault(RSADecryptKey, DefaultRSAPublic)
	viper.SetDefault(RSAPrivateKey, constant.EmptyString)
	viper.SetDefault(RSAPublicKey, constant.EmptyString)
	viper.SetDefault(InputKey, constant.EmptyString)
}

// ValidateConfig validates if the configuration is valid
func ValidateConfig() (err error) {
	merr := &multierror.Error{}

	// validate log section
	err = ValidateLog()
	if err != nil {
		merr = multierror.Append(merr, err)
	}
	// validate rsa section
	err = ValidateRSA()
	if err != nil {
		merr = multierror.Append(merr, err)
	}

	return errors.Trace(merr.ErrorOrNil())
}

// ValidateLog validates if log section is valid.
func ValidateLog() error {
	merr := &multierror.Error{}

	// validate log.level
	logLevel, err := cast.ToStringE(viper.Get(LogLevelKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}
	if !common.ElementInSlice(ValidLogLevels, logLevel) {
		merr = multierror.Append(merr, message.NewMessage(message.ErrNotValidLogLevel, logLevel))
	}
	// validate log.format
	logFormat, err := cast.ToStringE(viper.Get(LogFormatKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}
	if !common.ElementInSlice(ValidLogFormats, logFormat) {
		merr = multierror.Append(merr, message.NewMessage(message.ErrNotValidLogFormat, logFormat))
	}

	return merr.ErrorOrNil()
}

// ValidateRSA validates if rsa section is valid.
func ValidateRSA() error {
	merr := &multierror.Error{}

	// validate rsa.encrypt
	rsaEncrypt, err := cast.ToStringE(viper.Get(RSAEncryptKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}
	if !common.ElementInSlice(ValidKeyTypes, rsaEncrypt) {
		merr = multierror.Append(merr, message.NewMessage(msgRSA.ErrRSANotValidKeyType, rsaEncrypt))
	}
	// validate rsa.decrypt
	rsaDecrypt, err := cast.ToStringE(viper.Get(RSADecryptKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}
	if !common.ElementInSlice(ValidKeyTypes, rsaDecrypt) {
		merr = multierror.Append(merr, message.NewMessage(msgRSA.ErrRSANotValidKeyType, rsaDecrypt))
	}
	// validate rsa.private
	_, err = cast.ToStringE(viper.Get(RSAPrivateKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}
	// validate rsa.public
	_, err = cast.ToStringE(viper.Get(RSAPublicKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}
	// validate input
	_, err = cast.ToStringE(viper.Get(InputKey))
	if err != nil {
		merr = multierror.Append(merr, errors.Trace(err))
	}

	return merr.ErrorOrNil()
}

// TrimSpaceOfArg trims spaces of given argument
func TrimSpaceOfArg(arg string) string {
	args := strings.SplitN(arg, constant.EqualString, 2)

	switch len(args) {
	case 1:
		return strings.TrimSpace(args[0])
	case 2:
		argName := strings.TrimSpace(args[0])
		argValue := strings.TrimSpace(args[1])
		return fmt.Sprintf("%s=%s", argName, argValue)
	default:
		return arg
	}
}

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

package cmd

import (
	"fmt"
	"os"

	"github.com/romberli/go-util/constant"
	"github.com/romberli/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/romberli/go-rsa/config"
	"github.com/romberli/go-rsa/module/rsa"
	"github.com/romberli/go-rsa/pkg/message"

	rsaMessage "github.com/romberli/go-rsa/pkg/message/rsa"
)

const (
	encryptCommand = "encrypt"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypt command",
	Long:  `encrypt the message.`,
	Run: func(cmd *cobra.Command, args []string) {
		// init config
		err := initConfig()
		if err != nil {
			fmt.Println(fmt.Sprintf(constant.LogWithStackString, message.NewMessage(message.ErrInitConfig, err)))
			os.Exit(constant.DefaultAbnormalExitCode)
		}

		keyType = viper.GetString(config.KeyTypeKey)
		keyString = viper.GetString(config.KeyStringKey)
		input = viper.GetString(config.InputKey)

		switch keyType {
		case publicKeyType:
			output, err := rsa.EncryptWithPublicKeyString(keyType, keyString)
			if err != nil {
				log.Errorf(constant.LogWithStackString, message.NewMessage(rsaMessage.ErrRSAEncrypt, err, keyType, keyString, input))
				os.Exit(constant.DefaultAbnormalExitCode)
			}

			fmt.Println(output)
		case privateKeyType:
			output, err := rsa.EncryptWithPrivateKeyString(keyType, keyString)
			if err != nil {
				fmt.Println(fmt.Sprintf(constant.LogWithStackString, message.NewMessage(rsaMessage.ErrRSAEncrypt, err, keyType, keyString, input)))
				os.Exit(constant.DefaultAbnormalExitCode)
			}

			fmt.Println(output)
		default:
			fmt.Println(fmt.Sprintf(constant.LogWithStackString, message.NewMessage(rsaMessage.ErrRSANotValidKeyType, keyType)))
		}

		os.Exit(constant.DefaultNormalExitCode)
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

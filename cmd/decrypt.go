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

	msgRSA "github.com/romberli/go-rsa/pkg/message/rsa"
)

const decryptCommand = "decrypt"

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt command",
	Long:  `decrypt the cipher.`,
	Run: func(cmd *cobra.Command, args []string) {
		// init config
		err := initConfig()
		if err != nil {
			fmt.Println(fmt.Sprintf(constant.LogWithStackString, message.NewMessage(message.ErrInitConfig, err)))
			os.Exit(constant.DefaultAbnormalExitCode)
		}

		var output string

		rsaDecrypt = viper.GetString(config.RSADecryptKey)
		privateKey := viper.GetString(config.RSAPrivateKey)
		publicKey := viper.GetString(config.RSAPublicKey)
		input = viper.GetString(config.InputKey)

		switch rsaDecrypt {
		case config.DefaultRSAPrivate:
			output, err = rsa.DecryptWithPrivateKeyString(privateKey, input)
			if err != nil {
				log.Errorf(constant.LogWithStackString, message.NewMessage(msgRSA.ErrRSADecrypt, err, rsaDecrypt, privateKey, input))
				os.Exit(constant.DefaultAbnormalExitCode)
			}

			fmt.Println(output)
		case config.DefaultRSAPublic:
			output, err := rsa.DecryptWithPublicKeyString(publicKey, input)
			if err != nil {
				log.Errorf(constant.LogWithStackString, message.NewMessage(msgRSA.ErrRSADecrypt, err, rsaDecrypt, publicKey, input))
				os.Exit(constant.DefaultAbnormalExitCode)
			}

			fmt.Println(output)
		default:
			log.Errorf(constant.LogWithStackString, message.NewMessage(msgRSA.ErrRSANotValidKeyType, rsaDecrypt))
			os.Exit(constant.DefaultAbnormalExitCode)
		}

		os.Exit(constant.DefaultNormalExitCode)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

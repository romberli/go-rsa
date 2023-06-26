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
	"github.com/romberli/go-util/constant"
)

// global constant
const (
	DefaultCommandName = "rsa"
	DefaultBaseDir     = constant.CurrentDir

	DefaultRSAPrivate       = "private"
	DefaultRSAPublic        = "public"
	DefaultPublicKeyString  = "MEgCQQDJVV0o3zSnFIJnqs2xzjfAEmA2RNM8hLGvJfI9K9jT4YIDAuFSRGsyRDqqwqtJLhEVvsytAMKX22AR7Yeq95TdAgMBAAE="
	DefaultPrivateKeyString = "MIIBOwIBAAJBAMlVXSjfNKcUgmeqzbHON8ASYDZE0zyEsa8l8j0r2NPhggMC4VJEazJEOqrCq0kuERW+zK0AwpfbYBHth6r3lN0CAwEAAQJBALtM3/sLE6ewK9UXkH6usyzLq5gxFTcC125y5dXEudX6GDkQ7+c9WCMutDBF40D9xCvYfSVlNInBAGZVcC33WcECIQDRcFBwXIdXzj0lecjhkepkJHdC7+3zcDKx3lvj6rKxzQIhAPYXwhHL27AhvJ931dXL5tJGsajx5/xANAGZAn14+59RAiBbjfaL99buamjOfhtziB7nog1EhLAHcC+pE6Ql0Q5GrQIgUKSQcAyBvUIQ8aDvbdQXm6iW52n+P2c6o5tkeYF/00ECIQCyeOPbrbD8QMDkZzrvgKBMIG6ZW/hBTNXoTet0y3GB+Q=="
)

// configuration constant
const (
	LogLevelKey  = "log.level"
	LogFormatKey = "log.format"

	RSAEncryptKey = "rsa.encrypt"
	RSADecryptKey = "rsa.decrypt"
	RSAPrivateKey = "rsa.private"
	RSAPublicKey  = "rsa.public"
	InputKey      = "input"
)

package securestorage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"github.com/andsha/vconfig"
)

type SecureStorage struct {
	rsaKey  *rsa.PrivateKey
	confDir string
}

// Replaces ~ in a given path string into current user's home directory
func expandUser(path string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return strings.Replace(path, "~", usr.HomeDir, 1), nil
}

func NewSecureStorage(keyFile string, confDir string, configFile string) (*SecureStorage, error) {
	vc, err := vconfig.New(configFile)
	if err != nil {
		return nil, err
	}

	if keyFile == "" {
		// to get private key folder from environment variable
		keyDir, err := vc.GetSingleValue("", "KEY_DIR", "")
		if err != nil {
			return nil, err
		}

		// default private key folder. path inside home dir
		defaultKeyDir, err := vc.GetSingleValue("", "DEFAULT_KEY_DIR", "")
		if err != nil {
			return nil, err
		}

		// name of pem file
		pemFile, err := vc.GetSingleValue("", "PEM_FILE", "")
		if err != nil {
			return nil, err
		}

		// gettng full path to pem file
		envKeyDir, exists := os.LookupEnv(keyDir)
		var privateKey string

		if exists {
			privateKey = fmt.Sprintf("%v/%v", envKeyDir, pemFile)
		} else {
			userDirectory, err := expandUser("~")
			if err != nil {
				return nil, err
			}
			privateKey = fmt.Sprintf("%v/%v/%v", userDirectory, defaultKeyDir, pemFile)
		}

		keyFile = privateKey
	}

	if confDir == "" {
		confDirEnvName, err := vc.GetSingleValue("", "CONF_DIF", "")
		if err != nil {
			return nil, err
		}
		defaultConfDir, err := vc.GetSingleValue("", "DEFAULT_CONF_DIF", "")
		if err != nil {
			return nil, err
		}
		envConfDir, exists := os.LookupEnv(confDirEnvName)
		if !exists {
			envConfDir = defaultConfDir
		}
		confDir = envConfDir
	}

	ss := new(SecureStorage)
	ss.confDir = confDir
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	decodedKey, _ := pem.Decode(key)
	if decodedKey == nil {
		return nil, errors.New("Could not find encoded key in file")
	}
	ss.rsaKey, err = x509.ParsePKCS1PrivateKey(decodedKey.Bytes)
	if err != nil {
		return nil, err
	}
	//fmt.Println(vvss.rsaKey.Validate())
	ss.rsaKey.Precompute()

	return ss, nil
}

func (ss *SecureStorage) GetPasswordFromFile(file string) (string, error) {
	if !strings.HasPrefix(file, "/") {
		file = fmt.Sprintf("%s/%s", ss.confDir, file)
	}
	buff, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	pwd, err := decryptPassword(buff, ss)

	return string(pwd), nil
}

func (ss *SecureStorage) GetPasswordFromString(str string) (string, error) {
	buff, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	pwd, err := decryptPassword(buff, ss)

	return string(pwd), nil
}

func decryptPassword(buff []byte, ss *SecureStorage) (string, error) {
	pwd, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, ss.rsaKey, buff, nil)
	if err != nil {
		return "", err
	}

	return string(pwd), nil
}

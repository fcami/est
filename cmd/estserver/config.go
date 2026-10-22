/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// config contains the EST server configuration.
type config struct {
	MockCA              *mockCAConfig          `json:"mock_ca,omitempty"`
	TLS                 *tlsConfig             `json:"tls,omitempty"`
	AllowedHosts        []string               `json:"allowed_hosts,omitempty"`
	EnrollBasicAuth     *enrollBasicAuthConfig `json:"enroll_basic_auth,omitempty"`
	HealthCheckPassword string                 `json:"healthcheck_password"`
	RateLimit           int                    `json:"rate_limit"`
	Timeout             int                    `json:"timeout"`
	Logfile             string                 `json:"log_file"`
}

// mockCAConfig contains the mock CA configuration.
type mockCAConfig struct {
	Certs string `json:"certificates"`
	Key   string `json:"private_key"`
}

// enrollBasicAuthConfig contains the HTTP Basic Authentication credentials
// required to enroll. The password is read from PasswordFile when the
// configuration is loaded.
type enrollBasicAuthConfig struct {
	Username     string `json:"username"`
	PasswordFile string `json:"password_file"`
	password     string
}

// tlsConfig contains the server's TLS configuration.
type tlsConfig struct {
	ListenAddr string   `json:"listen_address"`
	Certs      string   `json:"certificates"`
	Key        string   `json:"private_key"`
	ClientCAs  []string `json:"client_cas,omitempty"`
}

// configFromFile returns a new EST server configuration from a JSON-encoded
// configuration file.
func configFromFile(filename string) (*config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.EnrollBasicAuth != nil {
		if err := cfg.EnrollBasicAuth.load(); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// load checks the user name and reads the password from the password file,
// without trailing CR and LF characters. RFC 7617 forbids a colon in the user
// name and control characters in both, so no client could send them.
func (c *enrollBasicAuthConfig) load() error {
	// Control characters are CTL in RFC 7617: bytes below 0x20 and 0x7f.
	// Unlike unicode.IsControl, this leaves the UTF-8 encoded U+0080 to
	// U+009F alone.
	isCTL := func(r rune) bool { return r < 0x20 || r == 0x7f }

	if c.Username == "" {
		return errors.New("enroll_basic_auth username is empty")
	}

	if strings.Contains(c.Username, ":") {
		return errors.New("enroll_basic_auth username contains a colon")
	}

	if strings.ContainsFunc(c.Username, isCTL) {
		return errors.New("enroll_basic_auth username contains a control character")
	}

	if c.PasswordFile == "" {
		return errors.New("enroll_basic_auth password_file is empty")
	}

	data, err := os.ReadFile(c.PasswordFile)
	if err != nil {
		return fmt.Errorf("failed to read enroll_basic_auth password file: %v", err)
	}

	c.password = strings.TrimRight(string(data), "\r\n")
	if c.password == "" {
		return errors.New("enroll_basic_auth password is empty")
	}

	if strings.ContainsFunc(c.password, isCTL) {
		return errors.New("enroll_basic_auth password contains a control character")
	}

	return nil
}

const sample = `{
    "mock_ca": {
        "certificates": "/path/to/CA/certificates.pem",
        "private_key": "/path/to/CA/private/key.pem"
    },
    "tls": {
        "listen_address": "localhost:8443",
        "certificates": "/path/to/server/certificates.pem",
        "private_key": "/path/to/server/private/key.pem",
        "client_cas": [
            "/path/to/first/client/CA/root/certificate.pem",
            "/path/to/second/client/CA/root/certificate.pem",
            "/path/to/third/client/CA/root/certificate.pem"
        ]
    },
    "allowed_hosts": [
        "localhost",
        "127.0.0.1",
        "[::1]"
    ],
    "enroll_basic_auth": {
        "username": "enroller",
        "password_file": "/path/to/enroll/password.txt"
    },
    "healthcheck_password": "xyzzy",
    "rate_limit": 150,
    "timeout": 30,
    "log_file": "/path/to/log.file"
}`

// sampleConfig outputs a sample configuration file.
func sampleConfig() {
	fmt.Println(sample)
}

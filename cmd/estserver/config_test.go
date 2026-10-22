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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFromFileEnrollBasicAuth(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name      string
		username  string
		password  string
		missing   bool
		want      string
		errSubstr string
	}{
		{
			name:     "OK",
			username: "enroll",
			password: "xyzzy",
			want:     "xyzzy",
		},
		{
			name:     "TrailingLF",
			username: "enroll",
			password: "xyzzy\n",
			want:     "xyzzy",
		},
		{
			name:     "TrailingCRLF",
			username: "enroll",
			password: "xyzzy\r\n",
			want:     "xyzzy",
		},
		{
			name:     "TrailingNewlines",
			username: "enroll",
			password: "xyzzy\n\n",
			want:     "xyzzy",
		},
		{
			name:     "OtherWhitespaceKept",
			username: "enroll",
			password: " xyzzy \n",
			want:     " xyzzy ",
		},
		{
			name:      "MissingPasswordFile",
			username:  "enroll",
			missing:   true,
			errSubstr: "failed to read enroll_basic_auth password file",
		},
		{
			name:      "EmptyPasswordFile",
			username:  "enroll",
			errSubstr: "enroll_basic_auth password is empty",
		},
		{
			name:      "NewlineOnlyPasswordFile",
			username:  "enroll",
			password:  "\r\n",
			errSubstr: "enroll_basic_auth password is empty",
		},
		{
			name:      "EmptyUsername",
			password:  "xyzzy",
			errSubstr: "enroll_basic_auth username is empty",
		},
		{
			name:      "ColonInUsername",
			username:  "en:roll",
			password:  "xyzzy",
			errSubstr: "enroll_basic_auth username contains a colon",
		},
		{
			name:      "ControlCharacterInUsername",
			username:  "en\troll",
			password:  "xyzzy",
			errSubstr: "enroll_basic_auth username contains a control character",
		},
		{
			name:      "TabInPassword",
			username:  "enroll",
			password:  "xy\tzzy\n",
			errSubstr: "enroll_basic_auth password contains a control character",
		},
		{
			name:      "LFInPassword",
			username:  "enroll",
			password:  "xy\nzzy\n",
			errSubstr: "enroll_basic_auth password contains a control character",
		},
		{
			name:     "ColonInPassword",
			username: "enroll",
			password: "xy:zzy",
			want:     "xy:zzy",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pwfile := filepath.Join(t.TempDir(), "password")
			if !tc.missing {
				mustWriteFile(t, pwfile, tc.password)
			}

			got, err := configFromString(t, fmt.Sprintf(
				`{"enroll_basic_auth": {"username": %q, "password_file": %q}}`,
				tc.username, pwfile))
			if tc.errSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("got error %v, want one containing %q", err, tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to read configuration file: %v", err)
			}

			if got.EnrollBasicAuth == nil {
				t.Fatal("got no enroll_basic_auth section, want one")
			}
			if got.EnrollBasicAuth.Username != tc.username {
				t.Fatalf("got username %q, want %q", got.EnrollBasicAuth.Username, tc.username)
			}
			if got.EnrollBasicAuth.password != tc.want {
				t.Fatalf("got password %q, want %q", got.EnrollBasicAuth.password, tc.want)
			}
		})
	}
}

// The password is given inline, with a "password" key, instead of in a file.
func TestConfigFromFileEnrollBasicAuthNoPasswordFile(t *testing.T) {
	t.Parallel()

	_, err := configFromString(t, `{"enroll_basic_auth": {"username": "enroll", "password": "xyzzy"}}`)

	const want = "enroll_basic_auth password_file is empty"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got error %v, want one containing %q", err, want)
	}
}

func TestConfigFromFileNoEnrollBasicAuth(t *testing.T) {
	t.Parallel()

	got, err := configFromString(t, "{}")
	if err != nil {
		t.Fatalf("failed to read configuration file: %v", err)
	}

	if got.EnrollBasicAuth != nil {
		t.Fatalf("got %+v, want no enroll_basic_auth section", got.EnrollBasicAuth)
	}
}

// configFromString writes data to a configuration file and returns the
// result of reading it with configFromFile.
func configFromString(t *testing.T, data string) (*config, error) {
	t.Helper()

	filename := filepath.Join(t.TempDir(), "estserver.cfg")
	mustWriteFile(t, filename, data)

	return configFromFile(filename)
}

// mustWriteFile writes data to a new file.
func mustWriteFile(t *testing.T, filename, data string) {
	t.Helper()

	if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
}

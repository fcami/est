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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/globalsign/est"
	"github.com/globalsign/est/internal/mockca"
)

const testTimeout = time.Second * 10

const (
	healthCheckPath = "/healthcheck"
	cacertsPath     = "/.well-known/est/cacerts"
	enrollPath      = "/.well-known/est/simpleenroll"
	enrollAPSPath   = "/.well-known/est/someaps/simpleenroll"
	reenrollPath    = "/.well-known/est/simplereenroll"
	keygenPath      = "/.well-known/est/serverkeygen"
	healthCheckUser = "healthcheck"
	clientAuthMsg   = "Client authentication"
	requestIDField  = "HTTP Request ID"
)

// credentials contains HTTP Basic Authentication credentials.
type credentials struct {
	username string
	password string
}

// enrollCreds are the credentials that enrollCfg requires to enroll.
var enrollCreds = &credentials{"enroller", "plugh"}

// enrollCfg is a configuration which requires enrollCreds to enroll. It is a
// variable rather than a function because newCheckBasicAuth only reads it.
var enrollCfg = &config{
	HealthCheckPassword: "xyzzy",
	EnrollBasicAuth: &enrollBasicAuthConfig{
		Username: enrollCreds.username,
		password: enrollCreds.password,
	},
}

func TestCheckBasicAuth(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		password string
		method   string
		path     string
		creds    *credentials
		cert     bool
		status   int
	}{
		{
			name:     "HealthCheck/NoCredentials",
			password: "xyzzy",
			method:   http.MethodGet,
			path:     healthCheckPath,
			status:   http.StatusUnauthorized,
		},
		{
			name:     "HealthCheck/WrongUser",
			password: "xyzzy",
			method:   http.MethodGet,
			path:     healthCheckPath,
			creds:    &credentials{"testuser", "xyzzy"},
			status:   http.StatusUnauthorized,
		},
		{
			name:     "HealthCheck/WrongPassword",
			password: "xyzzy",
			method:   http.MethodGet,
			path:     healthCheckPath,
			creds:    &credentials{healthCheckUser, "plugh"},
			status:   http.StatusUnauthorized,
		},
		{
			name:     "HealthCheck/RightCredentials",
			password: "xyzzy",
			method:   http.MethodGet,
			path:     healthCheckPath,
			creds:    &credentials{healthCheckUser, "xyzzy"},
			status:   http.StatusOK,
		},
		{
			name:   "HealthCheck/NoConfiguredPasswordEmptyPassword",
			method: http.MethodGet,
			path:   healthCheckPath,
			creds:  &credentials{healthCheckUser, ""},
			status: http.StatusOK,
		},
		{
			name:   "HealthCheck/NoConfiguredPasswordSomePassword",
			method: http.MethodGet,
			path:   healthCheckPath,
			creds:  &credentials{healthCheckUser, "xyzzy"},
			status: http.StatusUnauthorized,
		},
		{
			name:     "SimpleEnroll/NoCredentials",
			password: "xyzzy",
			method:   http.MethodPost,
			path:     enrollPath,
			status:   http.StatusOK,
		},
		{
			name:     "SimpleEnroll/WrongCredentials",
			password: "xyzzy",
			method:   http.MethodPost,
			path:     enrollPath,
			creds:    &credentials{"testuser", "plugh"},
			status:   http.StatusOK,
		},
		{
			name:     "SimpleEnrollAPS/NoCredentials",
			password: "xyzzy",
			method:   http.MethodPost,
			path:     enrollAPSPath,
			status:   http.StatusOK,
		},
		{
			name:   "SimpleReenroll/CertificateNoCredentials",
			method: http.MethodPost,
			path:   reenrollPath,
			cert:   true,
			status: http.StatusOK,
		},
		{
			name:   "SimpleReenroll/CredentialsNoCertificate",
			method: http.MethodPost,
			path:   reenrollPath,
			creds:  &credentials{"testuser", "plugh"},
			status: http.StatusForbidden,
		},
		{
			name:   "SimpleReenroll/NoCredentialsNoCertificate",
			method: http.MethodPost,
			path:   reenrollPath,
			status: http.StatusForbidden,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newTestServer(t, &config{HealthCheckPassword: tc.password})
			client, body := mustClientAndBody(t, s, tc.method, tc.cert)

			got, text := doRequest(t, client, tc.method, s.URL+tc.path, tc.creds, body)
			if got != tc.status {
				t.Fatalf("got status code %d, want %d; body: %q; log: %v", got, tc.status, text, s.rec.snapshot())
			}
		})
	}
}

func TestEnrollBasicAuth(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		method string
		path   string
		creds  *credentials
		cert   bool
		status int
	}{
		{
			name:   "SimpleEnroll/NoCredentials",
			method: http.MethodPost,
			path:   enrollPath,
			status: http.StatusUnauthorized,
		},
		{
			name:   "SimpleEnroll/WrongUser",
			method: http.MethodPost,
			path:   enrollPath,
			creds:  &credentials{"testuser", enrollCreds.password},
			status: http.StatusUnauthorized,
		},
		{
			name:   "SimpleEnroll/WrongPassword",
			method: http.MethodPost,
			path:   enrollPath,
			creds:  &credentials{enrollCreds.username, "xyzzy"},
			status: http.StatusUnauthorized,
		},
		{
			name:   "SimpleEnroll/HealthCheckCredentials",
			method: http.MethodPost,
			path:   enrollPath,
			creds:  &credentials{healthCheckUser, enrollCfg.HealthCheckPassword},
			status: http.StatusUnauthorized,
		},
		{
			name:   "SimpleEnroll/RightCredentials",
			method: http.MethodPost,
			path:   enrollPath,
			creds:  enrollCreds,
			status: http.StatusOK,
		},
		{
			name:   "SimpleEnrollAPS/NoCredentials",
			method: http.MethodPost,
			path:   enrollAPSPath,
			status: http.StatusUnauthorized,
		},
		{
			name:   "SimpleEnrollAPS/RightCredentials",
			method: http.MethodPost,
			path:   enrollAPSPath,
			creds:  enrollCreds,
			status: http.StatusOK,
		},
		{
			name:   "SimpleReenroll/CredentialsNoCertificate",
			method: http.MethodPost,
			path:   reenrollPath,
			creds:  enrollCreds,
			status: http.StatusForbidden,
		},
		{
			name:   "SimpleReenroll/CertificateNoCredentials",
			method: http.MethodPost,
			path:   reenrollPath,
			cert:   true,
			status: http.StatusOK,
		},
		{
			name:   "HealthCheck/NoCredentials",
			method: http.MethodGet,
			path:   healthCheckPath,
			status: http.StatusUnauthorized,
		},
		{
			name:   "HealthCheck/EnrollCredentials",
			method: http.MethodGet,
			path:   healthCheckPath,
			creds:  enrollCreds,
			status: http.StatusUnauthorized,
		},
		{
			name:   "HealthCheck/RightCredentials",
			method: http.MethodGet,
			path:   healthCheckPath,
			creds:  &credentials{healthCheckUser, enrollCfg.HealthCheckPassword},
			status: http.StatusOK,
		},
		{
			name:   "ServerKeyGen/NoCredentials",
			method: http.MethodPost,
			path:   keygenPath,
			status: http.StatusOK,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newTestServer(t, enrollCfg)
			client, body := mustClientAndBody(t, s, tc.method, tc.cert)

			got, text := doRequest(t, client, tc.method, s.URL+tc.path, tc.creds, body)
			if got != tc.status {
				t.Fatalf("got status code %d, want %d; body: %q; log: %v", got, tc.status, text, s.rec.snapshot())
			}
		})
	}
}

func TestClientAuthLog(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name       string
		method     string
		path       string
		creds      *credentials
		cert       bool
		authorized bool
		user       string
		subject    string
	}{
		{
			name:       "SimpleEnroll/Credentials",
			method:     http.MethodPost,
			path:       enrollPath,
			creds:      enrollCreds,
			authorized: true,
			user:       enrollCreds.username,
		},
		{
			name:       "SimpleEnroll/RejectedCredentials",
			method:     http.MethodPost,
			path:       enrollPath,
			creds:      &credentials{"testuser", "hunter2"},
			authorized: true,
			user:       "testuser",
		},
		{
			name:   "SimpleEnroll/NoCredentials",
			method: http.MethodPost,
			path:   enrollPath,
		},
		{
			name:    "SimpleReenroll/Certificate",
			method:  http.MethodPost,
			path:    reenrollPath,
			cert:    true,
			subject: "CN=Test Reenroll",
		},
		{
			name:       "HealthCheck/Credentials",
			method:     http.MethodGet,
			path:       healthCheckPath,
			creds:      &credentials{healthCheckUser, enrollCfg.HealthCheckPassword},
			authorized: true,
			user:       healthCheckUser,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newTestServer(t, enrollCfg)
			client, body := mustClientAndBody(t, s, tc.method, tc.cert)

			doRequest(t, client, tc.method, s.URL+tc.path, tc.creds, body)

			e := mustFindEntry(t, s.rec.snapshot(), clientAuthMsg)

			if got := e.fields["Authorization Presented"]; got != tc.authorized {
				t.Errorf("got Authorization Presented %v, want %v", got, tc.authorized)
			}

			if got := e.fields["Basic Auth User"]; got != tc.user {
				t.Errorf("got Basic Auth User %q, want %q", got, tc.user)
			}

			if got := e.fields["Client Certificate"]; got != tc.subject {
				t.Errorf("got Client Certificate %q, want %q", got, tc.subject)
			}

			if tc.creds != nil && strings.Contains(fmt.Sprint(s.rec.snapshot()), tc.creds.password) {
				t.Fatalf("password %q found in log: %v", tc.creds.password, s.rec.snapshot())
			}
		})
	}
}

func TestClientAuthLogOtherAuthorization(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		header string
		secret string
	}{
		{"UndecodableBasic", "Basic user:hunter2", "hunter2"},
		{"Bearer", "Bearer hunter2", "hunter2"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newTestServer(t, enrollCfg)

			r, err := http.NewRequest(http.MethodGet, s.URL+healthCheckPath, nil)
			if err != nil {
				t.Fatalf("failed to create new HTTP request: %v", err)
			}

			r.Header.Set("Authorization", tc.header)

			sendRequest(t, s.Client(), r)

			e := mustFindEntry(t, s.rec.snapshot(), clientAuthMsg)

			if got := e.fields["Authorization Presented"]; got != true {
				t.Errorf("got Authorization Presented %v, want true", got)
			}

			if got := e.fields["Basic Auth User"]; got != "" {
				t.Errorf("got Basic Auth User %q, want none", got)
			}

			if strings.Contains(fmt.Sprint(s.rec.snapshot()), tc.secret) {
				t.Fatalf("secret %q found in log: %v", tc.secret, s.rec.snapshot())
			}
		})
	}
}

func TestClientAuthLogRequestID(t *testing.T) {
	t.Parallel()

	s := newTestServer(t, &config{})

	for _, cn := range []string{"Test Enroll 1", "Test Enroll 2"} {
		doRequest(t, s.Client(), http.MethodPost, s.URL+enrollPath, nil, mustMakeBase64CSR(t, cn))
	}

	// /cacerts is not behind the check, so it must add no line.
	doRequest(t, s.Client(), http.MethodGet, s.URL+cacertsPath, nil, nil)

	// The library logs its "HTTP request" line when the handler returns,
	// which can be after the client has the response. Close waits for it.
	s.Close()

	entries := s.rec.snapshot()

	requestIDs := make(map[interface{}]bool)
	for _, e := range findEntries(entries, "HTTP request") {
		requestIDs[e.fields[requestIDField]] = true
	}

	var ids []interface{}
	for _, e := range findEntries(entries, clientAuthMsg) {
		id := e.fields[requestIDField]
		if id == "" || !requestIDs[id] {
			t.Errorf("got %s %q, want the ID of an HTTP request entry in %v", requestIDField, id, entries)
		}

		ids = append(ids, id)
	}

	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("got request IDs %q, want two different IDs", ids)
	}
}

// doRequest sends a request, with the given Basic Authentication credentials
// and base64-encoded PKCS#10 body if not nil, and returns the response status
// code and body.
func doRequest(
	t *testing.T,
	client *http.Client,
	method, url string,
	creds *credentials,
	body []byte,
) (int, string) {
	t.Helper()

	r, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create new HTTP request: %v", err)
	}

	if body != nil {
		r.Header.Set("Content-Type", "application/pkcs10")
		r.Header.Set("Content-Transfer-Encoding", "base64")
	}

	if creds != nil {
		r.SetBasicAuth(creds.username, creds.password)
	}

	return sendRequest(t, client, r)
}

// sendRequest sends a request and returns the response status code and body.
func sendRequest(t *testing.T, client *http.Client, r *http.Request) (int, string) {
	t.Helper()

	resp, err := client.Do(r)
	if err != nil {
		t.Fatalf("failed to execute HTTP request: %v", err)
	}

	text, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read HTTP response body: %v", err)
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("failed to close HTTP response body: %v", err)
	}

	return resp.StatusCode, string(text)
}

// mustClientAndBody returns the HTTP client and the request body for a test
// case. If cert is true, the client presents a certificate issued by the mock
// CA and the body is a CSR for the same subject, as /simplereenroll requires.
// Otherwise the client presents no certificate. The body is nil unless the
// method is POST.
func mustClientAndBody(t *testing.T, s *testServer, method string, cert bool) (*http.Client, []byte) {
	t.Helper()

	cn, client := "Test Enroll", s.Client()
	if cert {
		cn = "Test Reenroll"
		client = mustEnrollClient(t, s, cn)
	}

	if method != http.MethodPost {
		return client, nil
	}

	return client, mustMakeBase64CSR(t, cn)
}

// mustEnrollClient returns an HTTP client for the test server which presents
// a certificate with the given common name, issued by the mock CA.
func mustEnrollClient(t *testing.T, s *testServer, cn string) *http.Client {
	t.Helper()

	key, der := mustMakeCSR(t, cn)

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse certificate request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cert, err := s.ca.Enroll(ctx, csr, "", nil)
	if err != nil {
		t.Fatalf("failed to enroll with mock CA: %v", err)
	}

	caCerts, err := s.ca.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain CA certificates: %v", err)
	}

	tlsCert := tls.Certificate{PrivateKey: key}
	for _, c := range append([]*x509.Certificate{cert}, caCerts...) {
		tlsCert.Certificate = append(tlsCert.Certificate, c.Raw)
	}

	transport := s.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{tlsCert}

	return &http.Client{Transport: transport}
}

// logEntry is a message logged with one of the logger's methods, with the
// fields of the logger that logged it.
type logEntry struct {
	msg    string
	fields map[string]interface{}
}

// recorder records the messages logged by the server, which the server
// goroutine writes and the test goroutine reads.
type recorder struct {
	mu      sync.Mutex
	entries []logEntry
}

// snapshot returns the entries recorded so far.
func (r *recorder) snapshot() []logEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]logEntry(nil), r.entries...)
}

// recordingLogger is an est.Logger which records to a recorder.
type recordingLogger struct {
	rec    *recorder
	fields []interface{}
}

// Errorf records the formatted message.
func (l *recordingLogger) Errorf(format string, args ...interface{}) {
	l.record(fmt.Sprintf(format, args...))
}

// Errorw records msg with the logger's fields and keysAndValues.
func (l *recordingLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.record(msg, keysAndValues...)
}

// Infof records the formatted message.
func (l *recordingLogger) Infof(format string, args ...interface{}) {
	l.record(fmt.Sprintf(format, args...))
}

// Infow records msg with the logger's fields and keysAndValues.
func (l *recordingLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.record(msg, keysAndValues...)
}

// With returns a logger which records to the same recorder, with additional
// fields.
func (l *recordingLogger) With(keysAndValues ...interface{}) est.Logger {
	return &recordingLogger{rec: l.rec, fields: append(append([]interface{}(nil), l.fields...), keysAndValues...)}
}

// record appends an entry with msg and the fields of l and keysAndValues.
func (l *recordingLogger) record(msg string, keysAndValues ...interface{}) {
	e := logEntry{msg: msg, fields: make(map[string]interface{})}
	kvs := append(append([]interface{}(nil), l.fields...), keysAndValues...)
	for i := 0; i+1 < len(kvs); i += 2 {
		e.fields[fmt.Sprint(kvs[i])] = kvs[i+1]
	}

	l.rec.mu.Lock()
	defer l.rec.mu.Unlock()

	l.rec.entries = append(l.rec.entries, e)
}

// findEntries returns the entries with the given message.
func findEntries(entries []logEntry, msg string) []logEntry {
	var found []logEntry
	for _, e := range entries {
		if e.msg == msg {
			found = append(found, e)
		}
	}

	return found
}

// mustFindEntry returns the only entry with the given message.
func mustFindEntry(t *testing.T, entries []logEntry, msg string) logEntry {
	t.Helper()

	found := findEntries(entries, msg)
	if len(found) != 1 {
		t.Fatalf("got %d %q entries, want 1: %v", len(found), msg, entries)
	}

	return found[0]
}

// testServer is an EST server started for a test.
type testServer struct {
	*httptest.Server

	// ca is the CA behind the server, and the one it trusts for client
	// certificates.
	ca *mockca.MockCA

	// rec records what the server logs.
	rec *recorder
}

// newTestServer starts an EST server backed by a transient mock CA, with the
// Basic Authentication check built from cfg. Clients may present a
// certificate issued by that CA. The server logs to the returned recorder.
func newTestServer(t *testing.T, cfg *config) *testServer {
	t.Helper()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create new mock CA: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	caCerts, err := ca.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain CA certificates: %v", err)
	}

	rec := &recorder{}

	r, err := est.NewRouter(&est.ServerConfig{
		CA:             ca,
		Timeout:        testTimeout,
		Logger:         &recordingLogger{rec: rec},
		CheckBasicAuth: logClientAuth(newCheckBasicAuth(cfg)),
	})
	if err != nil {
		t.Fatalf("failed to create new router: %v", err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCerts[len(caCerts)-1])

	s := httptest.NewUnstartedServer(r)
	s.TLS = &tls.Config{
		ClientCAs:  clientCAs,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}
	s.StartTLS()
	t.Cleanup(s.Close)

	return &testServer{Server: s, ca: ca, rec: rec}
}

// mustMakeCSR returns a new private key and a DER CSR for it, with the given
// common name.
func mustMakeCSR(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("failed to create certificate request: %v", err)
	}

	return key, der
}

// mustMakeBase64CSR returns a base64-encoded DER CSR for a new key, with the
// given common name.
func mustMakeBase64CSR(t *testing.T, cn string) []byte {
	t.Helper()

	_, der := mustMakeCSR(t, cn)

	return []byte(base64.StdEncoding.EncodeToString(der))
}

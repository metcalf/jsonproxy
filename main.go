package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codahale/http-handlers/recovery"
	"github.com/codahale/http-handlers/service"
	_ "github.com/codahale/metrics/runtime" // Report runtime metrics
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/graceful"
)

// Specification describes the configuration parameters for jsonproxy
// In normal execution, they are read from environment variables
// on startup.
type Specification struct {
	// BindAddr is the address the proxy server will bind to
	BindAddr string
	// Port is the port proxy server will bind to
	Port int64
	// APIPrefix is the URL path prefix for accessing the jsonproxy API.
	// Requests beginning with this prefix go to the internal API for
	// e.g. generating new keys rather than being proxied.
	APIPrefix string `envconfig:"api_prefix"`
	// Secret is used to generate keys for use with the proxy given an existing
	// API key for the upstream API. It must be a series of 16, 32 or 64 bytes
	// encoded in hexadecimal.
	Secret string
	// RoleFile is a path to the file describing the available proxy roles.
	// You can see an example file referenced from the tests.
	RoleFile string `envconfig:"role_file"`
	// UpstreamURL is the URL of the upstream API that jsonproxy will proxy
	// to.
	UpstreamURL string `envconfig:"upstream_url"`
}

// Role defines the resources that are accessible given a key with a to a
// particular named role. It maps patterns of permitted (as for path.Match)
// URL paths to Rules describing how to handle that path.
type Role map[string]Rule

// Rule defines how the proxy will behave for a particular path pattern.
// Methods defines a list of allowed HTTP methods for the pattern (or '*'
// to allow any method). ResponseKeys defines a list of key patterns
// that will be permitted in the JSON response.
type Rule struct {
	Methods      []string `json:"methods"`
	ResponseKeys []string `json:"response_keys"`
}

const (
	envPrefix = "jsonproxy"
	httpGrace = 10 * time.Second
)

var defaultSpecification = Specification{
	BindAddr:  "127.0.0.1",
	Port:      8080,
	APIPrefix: "jsonproxy",
	RoleFile:  "test-roles.json",
}

func main() {
	spec := defaultSpecification
	err := envconfig.Process(envPrefix, &spec)
	if err != nil {
		log.Fatal(err.Error())
	}

	handler, closer, err := build(&spec)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer closer()

	httpAddr := net.JoinHostPort(spec.BindAddr, strconv.FormatInt(spec.Port, 10))
	srv := &http.Server{
		Handler: handler,
		Addr:    httpAddr,
	}

	log.Printf("Starting on %s. (event=application_start)", httpAddr)
	if err := graceful.ListenAndServe(srv, httpGrace); err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			log.Println("Shutting down. (event=application_stop)")
		} else {
			log.Fatalf("Shutting down with fatal error: %s (event=application_error)", err)
		}
	}
}

func build(spec *Specification) (http.Handler, func() error, error) {
	var closers []io.Closer
	closer := func() error {
		for _, c := range closers {
			if err := c.Close(); err != nil {
				return err
			}
		}
		return nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/debug/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/debug/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("Forced panic")
	})

	key := make([]byte, 16)
	if spec.Secret == defaultSpecification.Secret {
		log.Println("WARNING: Please supply a random hex encoded secret of 16, 32 or 64 bytes.")
		if _, err := rand.Read(key); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		key, err = hex.DecodeString(spec.Secret)
		if err != nil {
			return nil, closer, err
		}
	}

	roleFile, err := os.Open(spec.RoleFile)
	if err != nil {
		log.Fatalf("Unable to open RoleFile %s: %v", spec.RoleFile, err)
	}

	roles := make(map[string]Role)
	if err := json.NewDecoder(roleFile).Decode(&roles); err != nil {
		log.Fatalf("Unable to parse RoleFile %s: %v", spec.RoleFile, err)
	}

	auth, err := NewAuth(key)
	if err != nil {
		return nil, closer, err
	}

	api := API{
		KeyGen:     auth.Generate,
		KeyEncoder: base64.StdEncoding.EncodeToString,
		Roles:      roles,
	}

	prefix := "/" + spec.APIPrefix
	mux.Handle(prefix+"/", http.StripPrefix(prefix, api.Handler()))

	upstreamURL, err := url.Parse(spec.UpstreamURL)
	if err != nil {
		return nil, closer, err
	}

	proxy := Proxy{
		KeyOpener:   auth.Open,
		Roles:       roles,
		UpstreamURL: upstreamURL,
	}
	mux.Handle("/", &proxy)

	srv := service.New(mux, recovery.LogOnPanic)

	return srv, closer, nil
}

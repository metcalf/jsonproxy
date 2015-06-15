package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const (
	testResponseJSON = `{
  "id": 123,
  "secret": "stuff",
  "jobs": [
	{"name": "me", "day": "night"},
	{"other": "stuff"}
  ],
  "name": {
	"first": "Mister",
	"last": "T"
  }
}`
	testFilteredJSON = `{
  "id": 123,
  "jobs": [
	{"name": "me", "day": "night"},
	{"other": "stuff"}
  ]
}`
	testFilteredNameJSON = `{
  "name": {
    "first": "Mister"
  }
}`
)

func TestHealthcheck(t *testing.T) {
	s, closer, err := build(newTestSpecification())
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	srv := httptest.NewServer(s)
	defer srv.Close()

	res, err := http.DefaultClient.Get(srv.URL + "/debug/healthcheck")
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != 200 {
		t.Errorf("Received unexpected %d status from healthcheck: %#v", res.StatusCode, res)
	}
}

func TestGenerateKey(t *testing.T) {
	spec := newTestSpecification()
	s, closer, err := build(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	srv := httptest.NewServer(s)
	defer srv.Close()

	req := keyRequest{[]string{"foo"}, "bar"}
	key, err := generateKey(srv.URL+"/"+spec.APIPrefix, &req)
	if err != nil {
		t.Fatal(err)
	}

	if key == "" {
		t.Error("Got an empty key back from the API")
	}
}

func TestProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("foo", "bar")
		w.Write([]byte(testResponseJSON))
	}))
	defer upstream.Close()

	spec := newTestSpecification()
	spec.UpstreamURL = upstream.URL

	s, closer, err := build(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	srv := httptest.NewServer(s)
	defer srv.Close()

	req := keyRequest{[]string{"foo"}, "bar"}
	key, err := generateKey(srv.URL+"/"+spec.APIPrefix, &req)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path, method, expect string
	}{
		{"/foo", "GET", ""},
		{"/candidates", "GET", ""},
		{"/candidates/baz", "GET", testFilteredJSON},
		{"/candidates/baz", "POST", ""},
		{"/candidates/baz/boz", "GET", ""},
		{"/candidates/baz/boz/42", "GET", testFilteredNameJSON},
		{"/candidates/baz/boz/42", "POST", testFilteredNameJSON},
	}

	for _, c := range cases {
		req, err := http.NewRequest(c.method, srv.URL+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(string(keyBytes), "")
		req.Header.Set("Content-Type", "application/json")

		res, err := http.DefaultClient.Do(req)

		b, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}

		var expStatus int
		if c.expect == "" {
			expStatus = http.StatusUnauthorized
		} else {
			expStatus = http.StatusOK
		}

		if res.StatusCode != expStatus {
			t.Errorf("Expected status %d but got %d for %s %s (body: %s)",
				expStatus, res.StatusCode, c.method, c.path, b)
			continue
		}

		if c.expect == "" {
			continue
		}

		if res.Header.Get("foo") != "bar" {
			t.Errorf("Expected header to be proxied but got: %#v", res.Header)
		}

		var expect, actual interface{}
		if err := json.Unmarshal([]byte(c.expect), &expect); err != nil {
			t.Fatalf("Error %v parsing: %q", err, c.expect)
		}
		if err := json.Unmarshal(b, &actual); err != nil {
			t.Fatalf("Error %v parsing: %q", err, b)
		}

		if !reflect.DeepEqual(expect, actual) {
			t.Errorf("Response body is incorrect at %s. Expected\n%#v\n\tbut got\n%#v",
				c.path, expect, actual)
		}
	}
}

func newTestSpecification() *Specification {
	s := defaultSpecification
	s.Secret = "00000000000000000000000000000000"

	return &s
}

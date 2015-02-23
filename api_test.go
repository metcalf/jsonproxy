package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIGenerateKey(t *testing.T) {
	api := API{
		KeyGen:     testKeyGen,
		KeyEncoder: func(b []byte) string { return string(b) },
		Roles:      map[string]Role{"foo": Role{}},
	}

	expected := "foo\x00bar"

	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	req := keyRequest{[]string{"foo"}, "bar"}
	key, err := generateKey(srv.URL, &req)
	if err != nil {
		t.Fatal(err)
	}

	if key != expected {
		t.Fatalf("Expected key %q but got %q", expected, key)
	}
}

func generateKey(baseURL string, req *keyRequest) (string, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(req); err != nil {
		return "", err
	}

	u := baseURL + "/keys"
	res, err := http.DefaultClient.Post(u, "application/json", &b)
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if have, want := res.StatusCode, 200; have != want {
		return "", fmt.Errorf("Expected status %d but got %d with body %s", want, have, body)
	}

	var keyRes keyResponse
	if err := json.Unmarshal(body, &keyRes); err != nil {
		return "", fmt.Errorf("Error decoding response with code %d: %#v", res.StatusCode, err)
	}

	return keyRes.Key, nil
}

func testKeyGen(key *Key) ([]byte, error) {
	var buf bytes.Buffer

	for _, role := range key.Roles {
		if _, err := buf.WriteString(role); err != nil {
			return nil, err
		}
		if err := buf.WriteByte(0); err != nil {
			return nil, err
		}
	}
	if _, err := buf.WriteString(key.APIKey); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

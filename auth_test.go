package main

import (
	"reflect"
	"testing"
	"time"
)

func TestAuth(t *testing.T) {
	auth, err := NewAuth([]byte("1234567890123456"))
	if err != nil {
		t.Fatal(err)
	}

	key := Key{
		CreatedAt: time.Now(),
		Roles:     []string{"foo"},
		APIKey:    "bar",
	}

	ciphertext, err := auth.Generate(&key)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := auth.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(key, opened) {
		t.Fatalf("%v decrypted to %v", key, opened)
	}
}

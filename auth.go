package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

// NewAuth creates a new Auth the uses the given secret for encryption
// and decryption operations.
func NewAuth(secret []byte) (*Auth, error) {
	auth := Auth{}

	b, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	auth.block = b

	return &auth, nil
}

// Auth defines a set of methods for encrypting and decrypting the keys
// used with jsonproxy.
type Auth struct {
	block cipher.Block
}

// Key describes a set of roles associated with an upstream API key.
type Key struct {
	CreatedAt time.Time
	Roles     []string
	APIKey    string
}

// Generate encrypts a key using authenticated AES-GCM
func (a *Auth) Generate(key *Key) ([]byte, error) {
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now()
	}

	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, uint32(key.CreatedAt.Unix())); err != nil {
		return nil, err
	}
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

	aead, err := cipher.NewGCM(a.block)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 100; i++ {
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		// Avoid ciphertexts that contain the ':' character since
		// it's used as the delimiter in HTTP basic auth.
		ciphertext := aead.Seal(nonce, nonce, buf.Bytes(), nil)
		if !bytes.Contains(ciphertext, []byte(":")) {
			return ciphertext, nil
		}
	}

	return nil, errors.New("Failed to generate a valid ciphertext")
}

// Open decrpyts a key encrypted using the same secret
func (a *Auth) Open(ciphertext []byte) (*Key, error) {
	aead, err := cipher.NewGCM(a.block)
	if err != nil {
		return nil, err
	}

	ns := aead.NonceSize()
	if len(ciphertext) <= ns {
		return nil, errors.New("Provided key data is invalid")
	}

	data, err := aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, err
	}

	key := Key{}

	buf := bytes.NewBuffer(data)
	var ut uint32
	if err := binary.Read(buf, binary.BigEndian, &ut); err != nil {
		return nil, err
	}
	key.CreatedAt = time.Unix(int64(ut), 0)

	parts := bytes.Split(buf.Bytes(), []byte{0})
	key.Roles = make([]string, len(parts)-1)
	key.APIKey = string(parts[len(parts)-1])

	for i, b := range parts[:len(parts)-1] {
		key.Roles[i] = string(b)
	}

	return &key, nil
}

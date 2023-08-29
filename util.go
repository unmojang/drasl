package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jxskiss/base62"
	"log"
	"strings"
	"sync"
)

func Check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func Unwrap[T any](value T, e error) T {
	if e != nil {
		log.Fatal(e)
	}
	return value
}

func Ptr[T any](value T) *T {
	return &value
}

func PtrSlice[T any](in []T) []*T {
	out := make([]*T, len(in))
	i := 0
	for i < len(in) {
		out[i] = &in[i]
		i += 1
	}
	return out
}

func Contains[T comparable](slice []T, target T) bool {
	for _, el := range slice {
		if el == target {
			return true
		}
	}
	return false
}

func PtrEquals[T comparable](a *T, b *T) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func Truncate(data []byte, length int) []byte {
	if len(data) < length {
		newData := make([]byte, length)
		copy(newData, data)
		return newData
	}
	return data[:16]
}

func RandomHex(n uint) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func RandomBase62(n uint) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base62.EncodeToString(bytes), nil
}

// Wrap string s to lines of at most n bytes
func Wrap(s string, n int) string {
	var builder strings.Builder
	for {
		end := n
		if end > len(s) {
			end = len(s)
		}
		builder.WriteString(s[:end])
		s = s[end:]
		if len(s) > 0 {
			builder.WriteString("\n")
		} else {
			break
		}
	}
	return builder.String()
}

func SignSHA256(app *App, plaintext []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(plaintext)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA256, sum)
}

func SignSHA1(app *App, plaintext []byte) ([]byte, error) {
	hash := sha1.New()
	hash.Write(plaintext)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA1, sum)
}

type KeyedMutex struct {
	mutexes sync.Map
}

func (m *KeyedMutex) Lock(key string) func() {
	value, _ := m.mutexes.LoadOrStore(key, &sync.Mutex{})
	mtx := value.(*sync.Mutex)
	mtx.Lock()

	return func() { mtx.Unlock() }
}

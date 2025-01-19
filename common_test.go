package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCommon(t *testing.T) {
	t.Parallel()

	ts := &TestSuite{}

	config := testConfig()
	ts.Setup(config)
	defer ts.Teardown()

	t.Run("AEAD encrypt/decrypt", ts.testAEADEncryptDecrypt)
	t.Run("Encrypt/decrypt cookie value", ts.testEncryptDecryptCookieValue)

}

func (ts *TestSuite) testAEADEncryptDecrypt(t *testing.T) {
	plaintext := []byte("I am a cookie value")
	ciphertext, err := ts.App.AEADEncrypt(plaintext)
	assert.Nil(t, err)

	decrypted, err := ts.App.AEADDecrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func (ts *TestSuite) testEncryptDecryptCookieValue(t *testing.T) {
	plaintext := "I am a cookie value"
	ciphertext, err := ts.App.EncryptCookieValue(plaintext)
	assert.Nil(t, err)

	decrypted, err := ts.App.DecryptCookieValue(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}

package main

import (
	"container/list"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCommon(t *testing.T) {
	t.Parallel()

	ts := &TestSuite{}

	config := testConfig()
	ts.Setup(config)
	defer ts.Teardown()

	t.Run("AEAD encrypt/decrypt", ts.testAEADEncryptDecrypt)
	t.Run("Encrypt/decrypt cookie value", ts.testEncryptDecryptCookieValue)
	t.Run("Test cleanupHeartbeatLRU", ts.testCleanupHeartbeatLRU)

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

func (ts *TestSuite) testCleanupHeartbeatLRU(t *testing.T) {
	// initialize LRU and map
	ts.App.HeartbeatMutex.Lock()
	ts.App.HeartbeatLruList = list.New()
	ts.App.HeartbeatSaltMap = make(map[ServerKey]heartbeatSaltEntry)

	freshKey := ServerKey{IP: "10.0.0.1", Port: 25565}
	freshElem := ts.App.HeartbeatLruList.PushBack(freshKey)
	ts.App.HeartbeatSaltMap[freshKey] = heartbeatSaltEntry{
		Salt:      "fresh",
		Timestamp: time.Now().Add(-1 * time.Second),
		Elem:      freshElem,
	}

	expiredKey := ServerKey{IP: "10.0.0.2", Port: 25566}
	expiredElem := ts.App.HeartbeatLruList.PushBack(expiredKey)
	ts.App.HeartbeatSaltMap[expiredKey] = heartbeatSaltEntry{
		Salt:      "expired",
		Timestamp: time.Now().Add(-heartbeatLruTTL - 1*time.Second),
		Elem:      expiredElem,
	}
	ts.App.HeartbeatMutex.Unlock()

	// run cleanup
	ts.App.cleanupHeartbeatLRU()

	// verify expired entry removed, fresh entry retained
	ts.App.HeartbeatMutex.Lock()
	_, expiredExists := ts.App.HeartbeatSaltMap[expiredKey]
	assert.False(t, expiredExists, "expired entry should be removed")

	entry, freshExists := ts.App.HeartbeatSaltMap[freshKey]
	assert.True(t, freshExists, "fresh entry should remain")
	assert.Equal(t, "fresh", entry.Salt)

	// ensure only the fresh key remains in the LRU list
	count := 0
	for e := ts.App.HeartbeatLruList.Front(); e != nil; e = e.Next() {
		k := e.Value.(ServerKey)
		if k == freshKey {
			count++
		}
	}
	assert.Equal(t, 1, count, "LRU should contain exactly the fresh entry")
	ts.App.HeartbeatMutex.Unlock()
}

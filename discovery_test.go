package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryMinecraftClient(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}

	config := testConfig()
	ts.Setup(config)
	defer ts.Teardown()

	for _, path := range []string{
		"/discovery/minecraft/client",
		"/authlib-injector/discovery/minecraft/client",
		"/minecraft/client",
	} {
		t.Run(path, func(t *testing.T) {
			rec := ts.Get(t, ts.Server, path, nil, nil)
			assert.Equal(t, http.StatusOK, rec.Code)

			var response discoveryResponse
			assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
			assert.Equal(t, "prod", response.Environment)
			assert.Equal(t, "minecraft", response.Product)
		})
	}
}

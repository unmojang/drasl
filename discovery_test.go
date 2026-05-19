package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
)

func TestDiscoveryMinecraftClient(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}

	config := testConfig()
	ts.Setup(config)
	defer ts.Teardown()
	ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)
	token := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	for _, path := range []string{
		"/discovery/minecraft/client",
		"/minecraft/client",
	} {
		t.Run(path, func(t *testing.T) {
			rec := ts.Get(t, ts.Server, path, nil, nil)
			assert.Equal(t, http.StatusOK, rec.Code)

			var response DiscoveryResponse
			assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
			assert.Equal(t, "prod", response.Environment)
			assert.Equal(t, "minecraft", response.Product)
			endpoints := response.Discovery.Player.Endpoints
			assert.Equal(t, ts.App.ServicesURL+"/friends", endpoints.GetFriends.URI)
			assert.Equal(t, endpoints.GetFriends.URI, endpoints.UpdateFriends.URI)
			assert.Equal(t, ts.App.ServicesURL+"/presence", endpoints.UpdatePresence.URI)
			friendsURL, err := url.Parse(endpoints.GetFriends.URI)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, ts.Get(t, ts.Server, friendsURL.Path, nil, &token).Code)
			assert.Equal(t, http.StatusBadRequest, ts.PutJSON(t, ts.Server, friendsURL.Path,
				map[string]string{"updateType": "UNKNOWN"}, nil, &token).Code)
			presenceURL, err := url.Parse(endpoints.UpdatePresence.URI)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, ts.PostJSON(t, ts.Server, presenceURL.Path,
				presenceRequest{Status: presenceStatusOnline}, nil, &token).Code)
			if assert.NotNil(t, response.Discovery.Signaling) {
				endpoint := response.Discovery.Signaling.Endpoints
				configurationURL, err := url.Parse(endpoint.GetConfiguration.URI)
				assert.NoError(t, err)
				req := httptest.NewRequest(http.MethodGet, configurationURL.Path, nil)
				req.Header.Set(signalingHeaderAuth, token)
				configuration := httptest.NewRecorder()
				ts.Server.ServeHTTP(configuration, req)
				assert.Equal(t, http.StatusOK, configuration.Code)
				var body struct {
					Result struct {
						SignalingURI  string `json:"signalingUri"`
						PingFrequency string `json:"pingFrequency"`
					} `json:"result"`
				}
				assert.NoError(t, json.Unmarshal(configuration.Body.Bytes(), &body))
				assert.Equal(t, "00:01:00", body.Result.PingFrequency)
				assert.Equal(t, "wss://drasl.example.com/signaling"+signalingWSPath,
					strings.ReplaceAll(endpoint.Connect.URI, "{signalingUri}", body.Result.SignalingURI))
			}
		})
	}
}

func TestDiscoverySignalingPrefixAndDisabled(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		app := &App{
			Config:       &Config{BaseURL: "https://drasl.example.com/prefix", P2P: signalingConfig{Enable: enabled}},
			ServicesURL:  "https://drasl.example.com/prefix/services",
			DiscoveryURL: "https://drasl.example.com/prefix/discovery",
		}
		rec := httptest.NewRecorder()
		assert.NoError(t, app.DiscoveryMinecraftClient()(echo.New().NewContext(
			httptest.NewRequest(http.MethodGet, "/prefix/discovery/minecraft/client", nil), rec)))
		var response DiscoveryResponse
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		if !enabled {
			assert.Nil(t, response.Discovery.Signaling)
			assert.NotContains(t, rec.Body.String(), `"signaling"`)
		} else if assert.NotNil(t, response.Discovery.Signaling) {
			assert.Equal(t, "https://drasl.example.com/prefix/signaling"+signalingConfigPath,
				response.Discovery.Signaling.Endpoints.GetConfiguration.URI)
			assert.Equal(t, "{signalingUri}"+signalingWSPath, response.Discovery.Signaling.Endpoints.Connect.URI)
		}
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/url"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/labstack/echo/v5"
)

/*
discovery.minecraftservices.com
*/

type discoveryEndpoint struct {
	URI string `json:"uri"`
}

type discoveryTextureEndpoint struct {
	ValidURIs []string `json:"validUris"`
}

type discoveryAuthenticationEndpoints struct {
	GetPublicKeys discoveryEndpoint `json:"getPublicKeys"`
	LoginXbox     discoveryEndpoint `json:"loginXbox"`
}

type discoveryAuthentication struct {
	Endpoints discoveryAuthenticationEndpoints `json:"endpoints"`
}

type discoverySessionEndpoints struct {
	GetProfileByID discoveryEndpoint `json:"getProfileById"`
	Verify         discoveryEndpoint `json:"verify"`
	Join           discoveryEndpoint `json:"join"`
}

type discoverySession struct {
	Endpoints discoverySessionEndpoints `json:"endpoints"`
}

type discoveryPlayerEndpoints struct {
	UpdatePresence   discoveryEndpoint `json:"updatePresence"`
	SendReport       discoveryEndpoint `json:"sendReport"`
	GetAttributes    discoveryEndpoint `json:"getAttributes"`
	GetFriends       discoveryEndpoint `json:"getFriends"`
	GetCertificates  discoveryEndpoint `json:"getCertificates"`
	UpdateAttributes discoveryEndpoint `json:"updateAttributes"`
	UpdateFriends    discoveryEndpoint `json:"updateFriends"`
	GetBlocklist     discoveryEndpoint `json:"getBlocklist"`
}

type discoveryPlayer struct {
	Endpoints discoveryPlayerEndpoints `json:"endpoints"`
}

type discoveryProfilesEndpoints struct {
	GetManyByName discoveryEndpoint        `json:"getManyByName"`
	GetByName     discoveryEndpoint        `json:"getByName"`
	GetTexture    discoveryTextureEndpoint `json:"getTexture"`
}

type discoveryProfiles struct {
	Endpoints discoveryProfilesEndpoints `json:"endpoints"`
}

type discoveryTelemetryEndpoints struct {
	SendEvents discoveryEndpoint `json:"sendEvents"`
}

type discoveryTelemetry struct {
	Endpoints discoveryTelemetryEndpoints `json:"endpoints"`
}

type discoveryDiscovery struct {
	Authentication discoveryAuthentication `json:"authentication"`
	Session        discoverySession        `json:"session"`
	Player         discoveryPlayer         `json:"player"`
	Profiles       discoveryProfiles       `json:"profiles"`
	Telemetry      discoveryTelemetry      `json:"telemetry"`
}

type DiscoveryResponse struct {
	Environment string             `json:"environment"`
	Product     string             `json:"product"`
	Discovery   discoveryDiscovery `json:"discovery"`
}

func (app *App) DiscoveryMinecraftClient() func(c *echo.Context) error {
	notImplementedURI := Unwrap(url.JoinPath(app.DiscoveryURL, "not-implemented"))

	getTextureValidURIs := mapset.NewSet[string]()
	getTextureValidURIs.Add("/texture/skin/{textureId}")
	getTextureValidURIs.Add("/texture/cape/{textureId}")
	getTextureValidURIs.Add("/texture/default-skin/{textureId}")
	getTextureValidURIs.Add("/texture/default-cape/{textureId}")
	for _, fallbackAPIServer := range app.FallbackAPIServers {
		getTextureValidURIs = getTextureValidURIs.Union(fallbackAPIServer.GetTextureValidURIs)
	}

	responseBlob := Unwrap(json.Marshal(DiscoveryResponse{
		Environment: "prod",
		Product:     "minecraft",
		Discovery: discoveryDiscovery{
			Authentication: discoveryAuthentication{
				Endpoints: discoveryAuthenticationEndpoints{
					GetPublicKeys: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.ServicesURL, "publickeys")),
					},
					LoginXbox: discoveryEndpoint{
						URI: notImplementedURI,
					},
				},
			},
			Session: discoverySession{
				Endpoints: discoverySessionEndpoints{
					GetProfileByID: discoveryEndpoint{
						URI: app.SessionURL + "/session/minecraft/profile/{profileId}",
					},
					Verify: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.SessionURL, "session/minecraft/hasJoined")),
					},
					Join: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.SessionURL, "session/minecraft/join")),
					},
				},
			},
			Player: discoveryPlayer{
				Endpoints: discoveryPlayerEndpoints{
					UpdatePresence: discoveryEndpoint{
						URI: notImplementedURI,
					},
					SendReport: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.ServicesURL, "player/report")),
					},
					GetAttributes: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.ServicesURL, "player/attributes")),
					},
					GetFriends: discoveryEndpoint{
						URI: notImplementedURI,
					},
					GetCertificates: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.ServicesURL, "player/certificates")),
					},
					UpdateAttributes: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.ServicesURL, "player/attributes")),
					},
					UpdateFriends: discoveryEndpoint{
						URI: notImplementedURI,
					},
					GetBlocklist: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.ServicesURL, "privacy/blocklist")),
					},
				},
			},
			Profiles: discoveryProfiles{
				Endpoints: discoveryProfilesEndpoints{
					GetManyByName: discoveryEndpoint{
						URI: Unwrap(url.JoinPath(app.AccountURL, "profiles/minecraft")),
					},
					GetByName: discoveryEndpoint{
						URI: app.AccountURL + "/users/profiles/minecraft/{name}",
					},
					GetTexture: discoveryTextureEndpoint{
						ValidURIs: getTextureValidURIs.ToSlice(),
					},
				},
			},
			Telemetry: discoveryTelemetry{
				Endpoints: discoveryTelemetryEndpoints{
					SendEvents: discoveryEndpoint{
						URI: notImplementedURI,
					},
				},
			},
		},
	}))

	return func(c *echo.Context) error {
		return c.JSONBlob(http.StatusOK, responseBlob)
	}
}

func (app *App) DiscoveryNotImplemented() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		return c.NoContent(http.StatusNotImplemented)
	}
}
